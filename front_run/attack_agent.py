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
    

    def _extract_comment_from_url(self, comment_url: str) -> Tuple[Optional[str], Optional[int]]:
        """
        Parse a GitHub issue comment URL and return (repo_full_name, comment_id).
        Expected formats include:
          https://github.com/owner/repo/issues/<num>#issuecomment-<id>
          https://github.com/owner/repo/pull/<num>#issuecomment-<id>
        """
        try:
            parts = urlparse(comment_url)
            segs = parts.path.strip("/").split("/")
            if len(segs) < 2:
                return None, None
            owner = segs[0]
            repo = segs[1]
            # Find the issuecomment-<id> anchor in the fragment or in the URL string
            anchor = parts.fragment or ""
            m = re.search(r"issuecomment-(\d+)", anchor) or re.search(r"issuecomment-(\d+)", comment_url)
            if not m:
                return None, None
            comment_id = int(m.group(1))
            return f"{owner}/{repo}", comment_id
        except Exception:
            return None, None


    def remove_comment(
        self,
        comment_url: Optional[str] = None,
        *,
        repo: Optional[str] = None,
        comment_id: Optional[int] = None,
    ) -> bool:
        """
        Remove a GitHub issue comment.

        Usage:
          - By URL (recommended):
              remove_comment("https://github.com/owner/repo/issues/123#issuecomment-4567890")
          - Or by repo + id:
              remove_comment(repo="owner/repo", comment_id=4567890)

        Returns:
          True if (would) succeed, False otherwise.
        """
        # Resolve repo + id from URL if provided
        if comment_url:
            repo_from_url, id_from_url = self._extract_comment_from_url(comment_url)
            if not repo and repo_from_url:
                repo = repo_from_url
            if not comment_id and id_from_url:
                comment_id = id_from_url

        if not repo or not comment_id:
            print("[remove_comment] Missing repo or comment_id; provide a full comment URL or both 'repo' and 'comment_id'.")
            return False

        if DRY_RUN:
            print(f"[DRY_RUN] Would delete comment id={comment_id} in repo={repo}")
            return True

        try:
            gh_repo = self.gh.get_repo(repo)
            comment = gh_repo.get_issue_comment(comment_id)
            comment.delete()
            print(f"[AttackAgent] Deleted comment id={comment_id} in {repo}")
            return True
        except Exception as e:
            print(f"[AttackAgent] Failed to delete comment id={comment_id} in {repo}: {e}")
            return False

