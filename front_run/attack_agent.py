from typing import Optional, Tuple
from urllib.parse import urlparse
from github import Github
import re
import os

from .config import settings

DRY_RUN = os.getenv("DRY_RUN", "1") == "1"  # default to DRY_RUN for safety

class AttackAgent:
    def __init__(self, token: Optional[str] = None):
        token = token or settings.github_token
        if not token:
            raise ValueError("GITHUB_TOKEN is required")
        self.gh = Github(token)

    def _extract_issue(self, issue_url: str) -> Tuple[Optional[str], Optional[int]]:
        try:
            parts = urlparse(issue_url)
            segs = parts.path.strip("/").split("/")
            if len(segs) >= 4 and segs[-2] == "issues":
                owner = segs[-4]
                repo = segs[-3]
                num = int(segs[-1])
                return f"{owner}/{repo}", num
        except Exception:
            pass
        return None, None

    def comment_on_issue(self, issue_url: Optional[str], fallback_repo: str, message: str) -> Optional[str]:
        repo_name: Optional[str] = None
        num: Optional[int] = None
        if issue_url:
            repo_name, num = self._extract_issue(issue_url)

        if repo_name and num:
            if DRY_RUN:
                print(f"[DRY_RUN] Would post to issue: {repo_name}#{num}")
                print(f"[DRY_RUN] Message:\n{message}")
                return None
            repo = self.gh.get_repo(repo_name)
            issue = repo.get_issue(number=num)
            comment = issue.create_comment(message)
            return comment.html_url

        if not fallback_repo:
            raise RuntimeError("No usable issue URL and no fallback_repo configured.")

        repo = self.gh.get_repo(fallback_repo)
        issues = repo.get_issues(state="closed", sort="updated", direction="desc")
        for issue in issues:
            if getattr(issue, "pull_request", None) is not None:
                continue
            if DRY_RUN:
                print(f"[DRY_RUN] Would post to closed issue: {repo.full_name}#{issue.number}")
                print(f"[DRY_RUN] Message:\n{message}")
                return None
            comment = issue.create_comment(message)
            return comment.html_url

        raise RuntimeError("No closed issues found to comment on in fallback_repo.")
    

    def _extract_comment_info(self, comment_url: str) -> Tuple[Optional[str], Optional[int], Optional[int], Optional[bool]]:
        """
        Parse a GitHub comment URL and return:
        (repo_full_name, issue_or_pr_number, comment_id, is_pr_review_comment)

        Supported:
        - https://github.com/owner/repo/issues/123#issuecomment-4567890
        - https://github.com/owner/repo/pull/123#issuecomment-4567890
        - https://github.com/owner/repo/pull/123#discussion_r9876543   (PR *review* comment)
        """
        try:
            parts = urlparse(comment_url)
            segs = parts.path.strip("/").split("/")
            if len(segs) < 3:
                return None, None, None, None

            owner, repo = segs[0], segs[1]
            repo_full = f"{owner}/{repo}"

            # issue or pull number
            num = None
            if "issues" in segs and segs.index("issues") + 1 < len(segs):
                num = int(segs[segs.index("issues") + 1])
            elif "pull" in segs and segs.index("pull") + 1 < len(segs):
                num = int(segs[segs.index("pull") + 1])

            frag = parts.fragment or ""
            m_issue_comment = re.search(r"issuecomment-(\d+)", frag) or re.search(r"issuecomment-(\d+)", comment_url)
            m_review_comment = re.search(r"discussion_r(\d+)", frag) or re.search(r"discussion_r(\d+)", comment_url)

            if m_issue_comment:
                return repo_full, num, int(m_issue_comment.group(1)), False
            if m_review_comment:
                return repo_full, num, int(m_review_comment.group(1)), True

            return repo_full, num, None, None
        except Exception:
            return None, None, None, None

    def remove_comment(
        self,
        comment_url: Optional[str] = None,
        *,
        repo: Optional[str] = None,
        comment_id: Optional[int] = None,
        issue_number: Optional[int] = None,
    ) -> bool:
        """
        Remove a GitHub comment created on an issue/PR.
        Preferred usage: pass the full URL you got back from create_comment(...).

        - Issue/PR issue-comment URLs look like ...#issuecomment-<id>
        - PR review comments look like ...#discussion_r<id>

        Returns True if (would) succeed, False otherwise.
        """
        # Resolve from URL if provided
        is_pr_review = None
        if comment_url:
            repo_from_url, num_from_url, id_from_url, is_pr_review = self._extract_comment_info(comment_url)
            if not repo and repo_from_url:
                repo = repo_from_url
            if not issue_number and num_from_url:
                issue_number = num_from_url
            if not comment_id and id_from_url:
                comment_id = id_from_url

        if not repo or not comment_id:
            print("[remove_comment] Missing repo or comment_id; provide a full comment URL or both 'repo' and 'comment_id'.")
            return False

        if DRY_RUN or getattr(self, "gh", None) is None:
            print(f"[DRY_RUN] Would delete comment id={comment_id} in repo={repo} (issue_number={issue_number}, pr_review={is_pr_review})")
            return True

        try:
            gh_repo = self.gh.get_repo(repo)

            # PR review comment?
            if is_pr_review:
                try:
                    prc = gh_repo.get_pull_request_review_comment(comment_id)
                    prc.delete()
                    print(f"[AttackAgent] Deleted PR review comment id={comment_id} in {repo}")
                    return True
                except Exception as e:
                    print(f"[AttackAgent] Failed PR review comment delete id={comment_id}: {e}")
                    return False

            # Otherwise, regular issue/PR *issue* comment
            # Best-effort: if we have the issue number, search that thread first.
            if issue_number:
                try:
                    issue = gh_repo.get_issue(number=issue_number)
                    for c in issue.get_comments():
                        if c.id == comment_id:
                            c.delete()
                            print(f"[AttackAgent] Deleted issue comment id={comment_id} in {repo}#{issue_number}")
                            return True
                except Exception as e:
                    # fall through to repo-wide scan
                    print(f"[AttackAgent] Could not delete from issue thread directly, will try repo-wide: {e}")

            # Repo-wide scan (slower, but robust)
            for c in gh_repo.get_issues_comments():  # paginated; PyGithub handles paging
                if c.id == comment_id:
                    c.delete()
                    print(f"[AttackAgent] Deleted issue comment id={comment_id} in {repo} (repo-wide scan)")
                    return True

            print(f"[AttackAgent] Comment id={comment_id} not found in {repo}.")
            return False

        except Exception as e:
            print(f"[AttackAgent] Failed to delete comment id={comment_id} in {repo}: {e}")
            return False

