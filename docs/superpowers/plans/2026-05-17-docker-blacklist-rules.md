# Docker Blacklist Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 15 Docker/Docker-Compose blacklist rules to `rsh` across two new categories — volume destruction (data loss) and container/image cleanup.

**Architecture:** All rules are added to `RAW_RULES` in `src/blacklist.rs` following the existing `(id, category, bin, sub_pattern, reason)` tuple convention. Volume Destruction rules use `bin = Some("docker")` or `Some("docker-compose")` so the alias system works. The rule ID stability test is updated to include all 38 IDs.

**Tech Stack:** Rust, `regex` crate, existing `blacklist.rs` structure

---

## File Structure

- Modify: `src/blacklist.rs` — add rules to `RAW_RULES` and tests to the `tests` module

---

### Task 1: Docker — Volume Destruction rules (TDD)

**Files:**
- Modify: `src/blacklist.rs` — tests first, then rules, then update ID list

- [ ] **Step 1: Write failing tests**

  Add the following test functions inside the `#[cfg(test)] mod tests` block in `src/blacklist.rs`, after the existing `// ---- SQL — Destructive DDL ----` tests and before `// ---- General negative ----`:

  ```rust
  // ---- Docker — Volume Destruction ----

  #[test]
  fn blocks_docker_volume_rm() {
      assert!(blocks("docker volume rm mydata"));
      assert!(blocks("docker volume rm mydata otherdata"));
      assert!(blocks("docker volume rm -f mydata"));
      assert!(!blocks("docker volume ls"));
      assert!(!blocks("docker volume inspect mydata"));
  }

  #[test]
  fn blocks_docker_volume_prune() {
      assert!(blocks("docker volume prune"));
      assert!(blocks("docker volume prune -f"));
      assert!(!blocks("docker volume ls"));
  }

  #[test]
  fn blocks_docker_system_prune_risky() {
      assert!(blocks("docker system prune --volumes"));
      assert!(blocks("docker system prune -a"));
      assert!(blocks("docker system prune --all"));
      assert!(blocks("docker system prune -af"));
      assert!(blocks("docker system prune -f --volumes"));
      // Without risky flags stays allowed
      assert!(!blocks("docker system prune"));
      assert!(!blocks("docker system prune -f"));
  }

  #[test]
  fn blocks_docker_rm_volumes() {
      assert!(blocks("docker rm -v mycontainer"));
      assert!(blocks("docker rm -fv mycontainer"));
      assert!(blocks("docker rm --volumes mycontainer"));
      assert_eq!(hit_id("docker rm -v mycontainer"), Some("docker-rm-volumes"));
  }

  #[test]
  fn blocks_compose_down_volumes() {
      assert!(blocks("docker compose down -v"));
      assert!(blocks("docker compose down --volumes"));
      assert!(blocks("docker compose -f compose.yml down -v"));
      assert_eq!(hit_id("docker compose down -v"), Some("compose-down-volumes"));
  }

  #[test]
  fn blocks_compose_legacy_down_volumes() {
      assert!(blocks("docker-compose down -v"));
      assert!(blocks("docker-compose down --volumes"));
      assert!(blocks("docker-compose -f docker-compose.yml down -v"));
      assert_eq!(
          hit_id("docker-compose down -v"),
          Some("compose-legacy-down-volumes")
      );
  }

  #[test]
  fn blocks_compose_rm_volumes() {
      assert!(blocks("docker compose rm -v myservice"));
      assert!(blocks("docker compose rm --volumes"));
      assert_eq!(
          hit_id("docker compose rm -v myservice"),
          Some("compose-rm-volumes")
      );
  }

  #[test]
  fn blocks_compose_legacy_rm_volumes() {
      assert!(blocks("docker-compose rm -v myservice"));
      assert!(blocks("docker-compose rm --volumes myservice"));
      assert_eq!(
          hit_id("docker-compose rm -v"),
          Some("compose-legacy-rm-volumes")
      );
  }
  ```

- [ ] **Step 2: Run tests to verify they fail**

  ```bash
  cargo test blocks_docker_volume_rm blocks_docker_volume_prune blocks_docker_system_prune_risky blocks_docker_rm_volumes blocks_compose_down_volumes blocks_compose_legacy_down_volumes blocks_compose_rm_volumes blocks_compose_legacy_rm_volumes 2>&1 | grep -E "FAILED|error|test result"
  ```

  Expected: all 8 tests fail with `assertion failed` or `Some(...) != None`.

- [ ] **Step 3: Add Volume Destruction rules to `RAW_RULES`**

  In `src/blacklist.rs`, insert the following block immediately before the closing `];` of `RAW_RULES` (after the `sql-create-ddl` rule, which ends around line 225):

  ```rust
      // ---- Docker — Volume Destruction ----------------------------------
      (
          "docker-volume-rm",
          "Docker — Volume Destruction",
          Some("docker"),
          r"\s[^|;&\n]*?\bvolume\s+rm\b",
          "Removes named Docker volumes — irreversible data loss",
      ),
      (
          "docker-volume-prune",
          "Docker — Volume Destruction",
          Some("docker"),
          r"\s[^|;&\n]*?\bvolume\s+prune\b",
          "Removes all unused Docker volumes — bulk irreversible data loss",
      ),
      (
          "docker-system-prune-risky",
          "Docker — Volume Destruction",
          Some("docker"),
          r"\s[^|;&\n]*?\bsystem\s+prune\b[^|;&\n]*?(?:--volumes\b|--all\b|\s-[a-zA-Z]*a\b)",
          "system prune with --volumes or -a/--all deletes volumes and all images — high blast radius",
      ),
      (
          "docker-rm-volumes",
          "Docker — Volume Destruction",
          Some("docker"),
          r"\s[^|;&\n]*?\brm\b[^|;&\n]*?(?:--volumes\b|\s-[a-zA-Z]*v\b)",
          "Removes container and its anonymous volumes (-v) — irreversible data loss",
      ),
      (
          "compose-down-volumes",
          "Docker — Volume Destruction",
          Some("docker"),
          r"\s[^|;&\n]*?\bcompose\b[^|;&\n]*?\bdown\b[^|;&\n]*?(?:--volumes\b|\s-[a-zA-Z]*v\b)",
          "compose down -v removes all service containers and their volumes",
      ),
      (
          "compose-legacy-down-volumes",
          "Docker — Volume Destruction",
          Some("docker-compose"),
          r"\s[^|;&\n]*?\bdown\b[^|;&\n]*?(?:--volumes\b|\s-[a-zA-Z]*v\b)",
          "docker-compose down -v removes all service containers and their volumes",
      ),
      (
          "compose-rm-volumes",
          "Docker — Volume Destruction",
          Some("docker"),
          r"\s[^|;&\n]*?\bcompose\b[^|;&\n]*?\brm\b[^|;&\n]*?(?:--volumes\b|\s-[a-zA-Z]*v\b)",
          "compose rm -v removes stopped service containers and their anonymous volumes",
      ),
      (
          "compose-legacy-rm-volumes",
          "Docker — Volume Destruction",
          Some("docker-compose"),
          r"\s[^|;&\n]*?\brm\b[^|;&\n]*?(?:--volumes\b|\s-[a-zA-Z]*v\b)",
          "docker-compose rm -v removes stopped service containers and their anonymous volumes",
      ),
  ```

- [ ] **Step 4: Update the `rule_ids_are_distinct_and_match_expected_set` test**

  Replace the existing `expected` vector in that test with the full sorted list of 31 IDs (23 existing + 8 new):

  ```rust
  let expected = vec![
      "compose-down-volumes",
      "compose-legacy-down-volumes",
      "compose-legacy-rm-volumes",
      "compose-rm-volumes",
      "docker-rm-volumes",
      "docker-system-prune-risky",
      "docker-volume-prune",
      "docker-volume-rm",
      "helm-uninstall",
      "k8s-apply-remote",
      "k8s-attach",
      "k8s-cluster-admin-binding",
      "k8s-cp-inbound",
      "k8s-debug-node",
      "k8s-delete-all",
      "k8s-delete-clusterrole",
      "k8s-delete-crd",
      "k8s-delete-namespace",
      "k8s-delete-node",
      "k8s-delete-pv-pvc",
      "k8s-delete-workload",
      "k8s-drain",
      "k8s-exec-shell",
      "k8s-force-delete",
      "k8s-proxy",
      "k8s-run-privileged",
      "sql-alter-table",
      "sql-create-ddl",
      "sql-delete",
      "sql-drop",
      "sql-truncate",
  ];
  ```

- [ ] **Step 5: Run all tests**

  ```bash
  cargo test 2>&1 | tail -5
  ```

  Expected: `test result: ok. X passed; 0 failed`

- [ ] **Step 6: Commit**

  ```bash
  git add src/blacklist.rs
  git commit -m "feat(security): add Docker volume destruction blacklist rules"
  ```

---

### Task 2: Docker — Container/Image Cleanup rules (TDD)

**Files:**
- Modify: `src/blacklist.rs` — tests first, then rules, then update ID list

- [ ] **Step 1: Write failing tests**

  Add the following test functions immediately after the `blocks_compose_legacy_rm_volumes` test added in Task 1:

  ```rust
  // ---- Docker — Container/Image Cleanup ----

  #[test]
  fn blocks_docker_container_prune() {
      assert!(blocks("docker container prune"));
      assert!(blocks("docker container prune -f"));
      assert!(!blocks("docker container ls"));
      assert!(!blocks("docker container inspect foo"));
  }

  #[test]
  fn blocks_docker_image_prune() {
      assert!(blocks("docker image prune"));
      assert!(blocks("docker image prune -a"));
      assert!(blocks("docker image prune -f"));
      assert!(!blocks("docker image ls"));
      assert!(!blocks("docker image inspect foo"));
  }

  #[test]
  fn blocks_docker_image_rm() {
      assert!(blocks("docker image rm myimage:latest"));
      assert!(blocks("docker image remove myimage"));
      assert!(!blocks("docker image ls"));
      assert_eq!(hit_id("docker image rm myimage"), Some("docker-image-rm"));
  }

  #[test]
  fn blocks_docker_rmi() {
      assert!(blocks("docker rmi myimage:latest"));
      assert!(blocks("docker rmi myimage1 myimage2"));
      assert!(blocks("docker rmi -f myimage"));
      assert!(!blocks("docker run myimage"));
      assert_eq!(hit_id("docker rmi myimage"), Some("docker-rmi"));
  }

  #[test]
  fn blocks_docker_rm() {
      assert!(blocks("docker rm mycontainer"));
      assert!(blocks("docker rm -f mycontainer"));
      // rm -v fires docker-rm-volumes first (more specific rule)
      assert_eq!(hit_id("docker rm mycontainer"), Some("docker-rm"));
      assert!(!blocks("docker run myimage"));
      assert!(!blocks("docker ps"));
      assert!(!blocks("docker start mycontainer"));
  }

  #[test]
  fn blocks_compose_down() {
      assert!(blocks("docker compose down"));
      assert!(blocks("docker compose -f compose.yml down"));
      // down -v fires compose-down-volumes first
      assert_eq!(hit_id("docker compose down"), Some("compose-down"));
      assert!(!blocks("docker compose up"));
      assert!(!blocks("docker compose ps"));
  }

  #[test]
  fn blocks_compose_legacy_down() {
      assert!(blocks("docker-compose down"));
      assert!(blocks("docker-compose -f docker-compose.yml down"));
      // down -v fires compose-legacy-down-volumes first
      assert_eq!(hit_id("docker-compose down"), Some("compose-legacy-down"));
      assert!(!blocks("docker-compose up"));
      assert!(!blocks("docker-compose ps"));
  }
  ```

- [ ] **Step 2: Run tests to verify they fail**

  ```bash
  cargo test blocks_docker_container_prune blocks_docker_image_prune blocks_docker_image_rm blocks_docker_rmi blocks_docker_rm blocks_compose_down blocks_compose_legacy_down 2>&1 | grep -E "FAILED|error|test result"
  ```

  Expected: all 7 tests fail.

- [ ] **Step 3: Add Container/Image Cleanup rules to `RAW_RULES`**

  Append the following block immediately after the `compose-legacy-rm-volumes` rule added in Task 1 (still before `];`). Order matters: `docker-image-rm` and `docker-rmi` must appear before `docker-rm` so the more specific rules fire first for `docker image rm` and `docker rmi`.

  ```rust
      // ---- Docker — Container/Image Cleanup -----------------------------
      (
          "docker-container-prune",
          "Docker — Container/Image Cleanup",
          Some("docker"),
          r"\s[^|;&\n]*?\bcontainer\s+prune\b",
          "Removes all stopped containers in bulk",
      ),
      (
          "docker-image-prune",
          "Docker — Container/Image Cleanup",
          Some("docker"),
          r"\s[^|;&\n]*?\bimage\s+prune\b",
          "Removes dangling or all unused images",
      ),
      (
          "docker-image-rm",
          "Docker — Container/Image Cleanup",
          Some("docker"),
          r"\s[^|;&\n]*?\bimage\s+(?:rm|remove)\b",
          "Removes images by name or ID",
      ),
      (
          "docker-rmi",
          "Docker — Container/Image Cleanup",
          Some("docker"),
          r"\s[^|;&\n]*?\brmi\b\s+\S",
          "Removes images (legacy rmi command)",
      ),
      (
          "docker-rm",
          "Docker — Container/Image Cleanup",
          Some("docker"),
          r"\s[^|;&\n]*?\brm\b\s+\S",
          "Removes one or more containers",
      ),
      (
          "compose-down",
          "Docker — Container/Image Cleanup",
          Some("docker"),
          r"\s[^|;&\n]*?\bcompose\b[^|;&\n]*?\bdown\b",
          "Stops and removes all service containers (volumes kept without -v)",
      ),
      (
          "compose-legacy-down",
          "Docker — Container/Image Cleanup",
          Some("docker-compose"),
          r"\s[^|;&\n]*?\bdown\b",
          "Stops and removes all service containers (volumes kept without -v)",
      ),
  ```

- [ ] **Step 4: Update the `rule_ids_are_distinct_and_match_expected_set` test**

  Replace the `expected` vector with the full sorted list of 38 IDs:

  ```rust
  let expected = vec![
      "compose-down",
      "compose-down-volumes",
      "compose-legacy-down",
      "compose-legacy-down-volumes",
      "compose-legacy-rm-volumes",
      "compose-rm-volumes",
      "docker-container-prune",
      "docker-image-prune",
      "docker-image-rm",
      "docker-rm",
      "docker-rm-volumes",
      "docker-rmi",
      "docker-system-prune-risky",
      "docker-volume-prune",
      "docker-volume-rm",
      "helm-uninstall",
      "k8s-apply-remote",
      "k8s-attach",
      "k8s-cluster-admin-binding",
      "k8s-cp-inbound",
      "k8s-debug-node",
      "k8s-delete-all",
      "k8s-delete-clusterrole",
      "k8s-delete-crd",
      "k8s-delete-namespace",
      "k8s-delete-node",
      "k8s-delete-pv-pvc",
      "k8s-delete-workload",
      "k8s-drain",
      "k8s-exec-shell",
      "k8s-force-delete",
      "k8s-proxy",
      "k8s-run-privileged",
      "sql-alter-table",
      "sql-create-ddl",
      "sql-delete",
      "sql-drop",
      "sql-truncate",
  ];
  ```

- [ ] **Step 5: Run all tests**

  ```bash
  cargo test 2>&1 | tail -5
  ```

  Expected: `test result: ok. X passed; 0 failed`

- [ ] **Step 6: Commit**

  ```bash
  git add src/blacklist.rs
  git commit -m "feat(security): add Docker container and image cleanup blacklist rules"
  ```
