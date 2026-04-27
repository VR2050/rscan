package com.google.firebase.remoteconfig.internal;

import android.text.format.DateUtils;
import com.google.android.gms.common.util.Clock;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.Tasks;
import com.google.firebase.analytics.connector.AnalyticsConnector;
import com.google.firebase.iid.FirebaseInstanceId;
import com.google.firebase.remoteconfig.FirebaseRemoteConfigClientException;
import com.google.firebase.remoteconfig.FirebaseRemoteConfigException;
import com.google.firebase.remoteconfig.FirebaseRemoteConfigFetchThrottledException;
import com.google.firebase.remoteconfig.FirebaseRemoteConfigServerException;
import com.google.firebase.remoteconfig.internal.ConfigMetadataClient;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.net.HttpURLConnection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

/* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
/* JADX INFO: loaded from: classes.dex */
public class ConfigFetchHandler {
    static final int HTTP_TOO_MANY_REQUESTS = 429;
    private final AnalyticsConnector analyticsConnector;
    private final Clock clock;
    private final Map<String, String> customHttpHeaders;
    private final Executor executor;
    private final ConfigCacheClient fetchedConfigsCache;
    private final FirebaseInstanceId firebaseInstanceId;
    private final ConfigFetchHttpClient frcBackendApiClient;
    private final ConfigMetadataClient frcMetadata;
    private final Random randomGenerator;
    public static final long DEFAULT_MINIMUM_FETCH_INTERVAL_IN_SECONDS = TimeUnit.HOURS.toSeconds(12);
    static final int[] BACKOFF_TIME_DURATIONS_IN_MINUTES = {2, 4, 8, 16, 32, 64, 128, 256};

    public ConfigFetchHandler(FirebaseInstanceId firebaseInstanceId, AnalyticsConnector analyticsConnector, Executor executor, Clock clock, Random randomGenerator, ConfigCacheClient fetchedConfigsCache, ConfigFetchHttpClient frcBackendApiClient, ConfigMetadataClient frcMetadata, Map<String, String> customHttpHeaders) {
        this.firebaseInstanceId = firebaseInstanceId;
        this.analyticsConnector = analyticsConnector;
        this.executor = executor;
        this.clock = clock;
        this.randomGenerator = randomGenerator;
        this.fetchedConfigsCache = fetchedConfigsCache;
        this.frcBackendApiClient = frcBackendApiClient;
        this.frcMetadata = frcMetadata;
        this.customHttpHeaders = customHttpHeaders;
    }

    public Task<FetchResponse> fetch() {
        return fetch(this.frcMetadata.getMinimumFetchIntervalInSeconds());
    }

    public Task<FetchResponse> fetch(long minimumFetchIntervalInSeconds) {
        long fetchIntervalInSeconds = this.frcMetadata.isDeveloperModeEnabled() ? 0L : minimumFetchIntervalInSeconds;
        return this.fetchedConfigsCache.get().continueWithTask(this.executor, ConfigFetchHandler$$Lambda$1.lambdaFactory$(this, fetchIntervalInSeconds));
    }

    static /* synthetic */ Task lambda$fetch$0(ConfigFetchHandler configFetchHandler, long fetchIntervalInSeconds, Task cachedFetchConfigsTask) throws Exception {
        return configFetchHandler.fetchIfCacheExpiredAndNotThrottled(cachedFetchConfigsTask, fetchIntervalInSeconds);
    }

    private Task<FetchResponse> fetchIfCacheExpiredAndNotThrottled(Task<ConfigContainer> cachedFetchConfigsTask, long minimumFetchIntervalInSeconds) {
        Task<FetchResponse> fetchResponseTask;
        Date currentTime = new Date(this.clock.currentTimeMillis());
        if (cachedFetchConfigsTask.isSuccessful() && areCachedFetchConfigsValid(minimumFetchIntervalInSeconds, currentTime)) {
            return Tasks.forResult(FetchResponse.forLocalStorageUsed(currentTime));
        }
        Date backoffEndTime = getBackoffEndTimeInMillis(currentTime);
        if (backoffEndTime != null) {
            fetchResponseTask = Tasks.forException(new FirebaseRemoteConfigFetchThrottledException(createThrottledMessage(backoffEndTime.getTime() - currentTime.getTime()), backoffEndTime.getTime()));
        } else {
            fetchResponseTask = fetchFromBackendAndCacheResponse(currentTime);
        }
        return fetchResponseTask.continueWithTask(this.executor, ConfigFetchHandler$$Lambda$2.lambdaFactory$(this, currentTime));
    }

    static /* synthetic */ Task lambda$fetchIfCacheExpiredAndNotThrottled$1(ConfigFetchHandler configFetchHandler, Date currentTime, Task completedFetchTask) throws Exception {
        configFetchHandler.updateLastFetchStatusAndTime(completedFetchTask, currentTime);
        return completedFetchTask;
    }

    private boolean areCachedFetchConfigsValid(long cacheExpirationInSeconds, Date newFetchTime) {
        Date lastSuccessfulFetchTime = this.frcMetadata.getLastSuccessfulFetchTime();
        if (lastSuccessfulFetchTime.equals(ConfigMetadataClient.LAST_FETCH_TIME_NO_FETCH_YET)) {
            return false;
        }
        Date cacheExpirationTime = new Date(lastSuccessfulFetchTime.getTime() + TimeUnit.SECONDS.toMillis(cacheExpirationInSeconds));
        return newFetchTime.before(cacheExpirationTime);
    }

    private Date getBackoffEndTimeInMillis(Date currentTime) {
        Date backoffEndTime = this.frcMetadata.getBackoffMetadata().getBackoffEndTime();
        if (currentTime.before(backoffEndTime)) {
            return backoffEndTime;
        }
        return null;
    }

    private String createThrottledMessage(long throttledDurationInMillis) {
        return String.format("Fetch is throttled. Please wait before calling fetch again: %s", DateUtils.formatElapsedTime(TimeUnit.MILLISECONDS.toSeconds(throttledDurationInMillis)));
    }

    private Task<FetchResponse> fetchFromBackendAndCacheResponse(Date fetchTime) {
        try {
            FetchResponse fetchResponse = fetchFromBackend(fetchTime);
            if (fetchResponse.getStatus() != 0) {
                return Tasks.forResult(fetchResponse);
            }
            return this.fetchedConfigsCache.put(fetchResponse.getFetchedConfigs()).onSuccessTask(this.executor, ConfigFetchHandler$$Lambda$3.lambdaFactory$(fetchResponse));
        } catch (FirebaseRemoteConfigException frce) {
            return Tasks.forException(frce);
        }
    }

    static /* synthetic */ Task lambda$fetchFromBackendAndCacheResponse$2(FetchResponse fetchResponse, ConfigContainer putContainer) throws Exception {
        return Tasks.forResult(fetchResponse);
    }

    private FetchResponse fetchFromBackend(Date currentTime) throws FirebaseRemoteConfigException {
        try {
            HttpURLConnection urlConnection = this.frcBackendApiClient.createHttpURLConnection();
            FetchResponse response = this.frcBackendApiClient.fetch(urlConnection, this.firebaseInstanceId.getId(), this.firebaseInstanceId.getToken(), getUserProperties(), this.frcMetadata.getLastFetchETag(), this.customHttpHeaders, currentTime);
            if (response.getLastFetchETag() != null) {
                this.frcMetadata.setLastFetchETag(response.getLastFetchETag());
            }
            this.frcMetadata.resetBackoff();
            return response;
        } catch (FirebaseRemoteConfigServerException serverHttpError) {
            ConfigMetadataClient.BackoffMetadata backoffMetadata = updateAndReturnBackoffMetadata(serverHttpError.getHttpStatusCode(), currentTime);
            if (shouldThrottle(backoffMetadata, serverHttpError.getHttpStatusCode())) {
                throw new FirebaseRemoteConfigFetchThrottledException(backoffMetadata.getBackoffEndTime().getTime());
            }
            throw createExceptionWithGenericMessage(serverHttpError);
        }
    }

    private FirebaseRemoteConfigServerException createExceptionWithGenericMessage(FirebaseRemoteConfigServerException httpError) throws FirebaseRemoteConfigClientException {
        String errorMessage;
        int httpStatusCode = httpError.getHttpStatusCode();
        if (httpStatusCode == 401) {
            errorMessage = "The request did not have the required credentials. Please make sure your google-services.json is valid.";
        } else if (httpStatusCode == 403) {
            errorMessage = "The user is not authorized to access the project. Please make sure you are using the API key that corresponds to your Firebase project.";
        } else {
            if (httpStatusCode == HTTP_TOO_MANY_REQUESTS) {
                throw new FirebaseRemoteConfigClientException("The throttled response from the server was not handled correctly by the FRC SDK.");
            }
            if (httpStatusCode == 500) {
                errorMessage = "There was an internal server error.";
            } else {
                switch (httpStatusCode) {
                    case 502:
                    case 503:
                    case 504:
                        errorMessage = "The server is unavailable. Please try again later.";
                        break;
                    default:
                        errorMessage = "The server returned an unexpected error.";
                        break;
                }
            }
        }
        return new FirebaseRemoteConfigServerException(httpError.getHttpStatusCode(), "Fetch failed: " + errorMessage, httpError);
    }

    private ConfigMetadataClient.BackoffMetadata updateAndReturnBackoffMetadata(int statusCode, Date currentTime) {
        if (isThrottleableServerError(statusCode)) {
            updateBackoffMetadataWithLastFailedFetchTime(currentTime);
        }
        return this.frcMetadata.getBackoffMetadata();
    }

    private boolean isThrottleableServerError(int httpStatusCode) {
        return httpStatusCode == HTTP_TOO_MANY_REQUESTS || httpStatusCode == 502 || httpStatusCode == 503 || httpStatusCode == 504;
    }

    private void updateBackoffMetadataWithLastFailedFetchTime(Date lastFailedFetchTime) {
        int numFailedFetches = this.frcMetadata.getBackoffMetadata().getNumFailedFetches() + 1;
        long backoffDurationInMillis = getRandomizedBackoffDurationInMillis(numFailedFetches);
        Date backoffEndTime = new Date(lastFailedFetchTime.getTime() + backoffDurationInMillis);
        this.frcMetadata.setBackoffMetadata(numFailedFetches, backoffEndTime);
    }

    private long getRandomizedBackoffDurationInMillis(int numFailedFetches) {
        TimeUnit timeUnit = TimeUnit.MINUTES;
        int[] iArr = BACKOFF_TIME_DURATIONS_IN_MINUTES;
        long timeOutDurationInMillis = timeUnit.toMillis(iArr[Math.min(numFailedFetches, iArr.length) - 1]);
        return (timeOutDurationInMillis / 2) + ((long) this.randomGenerator.nextInt((int) timeOutDurationInMillis));
    }

    private boolean shouldThrottle(ConfigMetadataClient.BackoffMetadata backoffMetadata, int httpStatusCode) {
        return backoffMetadata.getNumFailedFetches() > 1 || httpStatusCode == HTTP_TOO_MANY_REQUESTS;
    }

    private void updateLastFetchStatusAndTime(Task<FetchResponse> completedFetchTask, Date fetchTime) {
        if (completedFetchTask.isSuccessful()) {
            this.frcMetadata.updateLastFetchAsSuccessfulAt(fetchTime);
            return;
        }
        Exception fetchException = completedFetchTask.getException();
        if (fetchException == null) {
            return;
        }
        if (fetchException instanceof FirebaseRemoteConfigFetchThrottledException) {
            this.frcMetadata.updateLastFetchAsThrottled();
        } else {
            this.frcMetadata.updateLastFetchAsFailed();
        }
    }

    private Map<String, String> getUserProperties() {
        Map<String, String> userPropertiesMap = new HashMap<>();
        AnalyticsConnector analyticsConnector = this.analyticsConnector;
        if (analyticsConnector == null) {
            return userPropertiesMap;
        }
        for (Map.Entry<String, Object> userPropertyEntry : analyticsConnector.getUserProperties(false).entrySet()) {
            userPropertiesMap.put(userPropertyEntry.getKey(), userPropertyEntry.getValue().toString());
        }
        return userPropertiesMap;
    }

    public AnalyticsConnector getAnalyticsConnector() {
        return this.analyticsConnector;
    }

    /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
    public static class FetchResponse {
        private final Date fetchTime;
        private final ConfigContainer fetchedConfigs;
        private final String lastFetchETag;
        private final int status;

        /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
        @Retention(RetentionPolicy.SOURCE)
        public @interface Status {
            public static final int BACKEND_HAS_NO_UPDATES = 1;
            public static final int BACKEND_UPDATES_FETCHED = 0;
            public static final int LOCAL_STORAGE_USED = 2;
        }

        private FetchResponse(Date fetchTime, int status, ConfigContainer fetchedConfigs, String lastFetchETag) {
            this.fetchTime = fetchTime;
            this.status = status;
            this.fetchedConfigs = fetchedConfigs;
            this.lastFetchETag = lastFetchETag;
        }

        public static FetchResponse forBackendUpdatesFetched(ConfigContainer fetchedConfigs, String lastFetchETag) {
            return new FetchResponse(fetchedConfigs.getFetchTime(), 0, fetchedConfigs, lastFetchETag);
        }

        public static FetchResponse forBackendHasNoUpdates(Date fetchTime) {
            return new FetchResponse(fetchTime, 1, null, null);
        }

        public static FetchResponse forLocalStorageUsed(Date fetchTime) {
            return new FetchResponse(fetchTime, 2, null, null);
        }

        Date getFetchTime() {
            return this.fetchTime;
        }

        String getLastFetchETag() {
            return this.lastFetchETag;
        }

        int getStatus() {
            return this.status;
        }

        public ConfigContainer getFetchedConfigs() {
            return this.fetchedConfigs;
        }
    }
}
