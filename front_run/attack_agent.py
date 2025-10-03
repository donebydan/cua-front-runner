# poc/attack_agent.py
from typing import Optional, Tuple
from urllib.parse import urlparse
from github import Github
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
