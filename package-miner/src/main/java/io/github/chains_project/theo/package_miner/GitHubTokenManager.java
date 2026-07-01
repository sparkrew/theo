package io.github.chains_project.theo.package_miner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Manages GitHub personal access tokens for API requests and git operations.
 * Supports multiple tokens with round-robin rotation and rate-limit awareness.
 *
 * Tokens are read from a text file (one per line, # comments and blank lines skipped).
 * When a token's rate limit is exhausted, the manager switches to the next available token.
 * If all tokens are exhausted, it blocks until the earliest reset time.
 */
public class GitHubTokenManager {

    private static final Logger log = LoggerFactory.getLogger(GitHubTokenManager.class);

    private final List<TokenState> tokens = new ArrayList<>();
    private int currentIndex = 0;

    private static class TokenState {
        final String token;
        int remaining = 5000;
        long resetEpochSeconds = 0;

        TokenState(String token) {
            this.token = token;
        }
    }

    public GitHubTokenManager(Path tokensFile) throws IOException {
        List<String> lines = Files.readAllLines(tokensFile);
        for (String line : lines) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                tokens.add(new TokenState(trimmed));
            }
        }
        if (tokens.isEmpty()) {
            throw new IllegalArgumentException("No tokens found in " + tokensFile);
        }
        log.info("Loaded {} GitHub token(s) from {}", tokens.size(), tokensFile);
    }

    /**
     * Returns the next available token, blocking if all are rate-limited.
     */
    public synchronized String getToken() {
        long now = System.currentTimeMillis() / 1000;

        for (int attempts = 0; attempts < tokens.size(); attempts++) {
            TokenState ts = tokens.get(currentIndex);
            if (ts.remaining > 50 || now >= ts.resetEpochSeconds) {
                return ts.token;
            }
            currentIndex = (currentIndex + 1) % tokens.size();
        }

        // All tokens exhausted — find the earliest reset and wait
        long earliestReset = Long.MAX_VALUE;
        for (TokenState ts : tokens) {
            earliestReset = Math.min(earliestReset, ts.resetEpochSeconds);
        }
        long waitMs = Math.max(1000, (earliestReset - now + 1) * 1000);
        log.warn("All GitHub tokens exhausted. Waiting {} seconds for rate limit reset...", waitMs / 1000);
        try {
            wait(waitMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        // After waiting, reset remaining for tokens whose reset time has passed
        now = System.currentTimeMillis() / 1000;
        for (TokenState ts : tokens) {
            if (now >= ts.resetEpochSeconds) {
                ts.remaining = 5000;
            }
        }
        return tokens.get(currentIndex).token;
    }

    /**
     * Updates the rate limit state for a token after a GitHub API response.
     */
    public synchronized void reportRateLimit(String token, int remaining, long resetEpochSeconds) {
        for (TokenState ts : tokens) {
            if (ts.token.equals(token)) {
                ts.remaining = remaining;
                ts.resetEpochSeconds = resetEpochSeconds;
                if (remaining < 50) {
                    log.info("Token ...{} nearly exhausted ({} remaining), rotating.",
                            token.substring(Math.max(0, token.length() - 4)), remaining);
                    currentIndex = (currentIndex + 1) % tokens.size();
                    notifyAll();
                }
                break;
            }
        }
    }

    /**
     * Marks a token as exhausted (e.g. after HTTP 403/429).
     */
    public synchronized void reportExhausted(String token, long resetEpochSeconds) {
        reportRateLimit(token, 0, resetEpochSeconds);
    }

    /**
     * Returns a clone URL with the token embedded for authentication.
     */
    public String formatCloneUrl(String githubUrl) {
        String token = getToken();
        // https://github.com/owner/repo → https://TOKEN@github.com/owner/repo.git
        String url = githubUrl.endsWith(".git") ? githubUrl : githubUrl + ".git";
        return url.replace("https://", "https://" + token + "@");
    }

    public int tokenCount() {
        return tokens.size();
    }
}
