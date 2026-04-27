package com.google.firebase.remoteconfig;

import android.content.Context;
import android.content.SharedPreferences;
import com.google.android.gms.common.util.Clock;
import com.google.android.gms.common.util.DefaultClock;
import com.google.android.gms.tasks.Tasks;
import com.google.firebase.FirebaseApp;
import com.google.firebase.abt.FirebaseABTesting;
import com.google.firebase.analytics.connector.AnalyticsConnector;
import com.google.firebase.iid.FirebaseInstanceId;
import com.google.firebase.remoteconfig.internal.ConfigCacheClient;
import com.google.firebase.remoteconfig.internal.ConfigFetchHandler;
import com.google.firebase.remoteconfig.internal.ConfigFetchHttpClient;
import com.google.firebase.remoteconfig.internal.ConfigGetParameterHandler;
import com.google.firebase.remoteconfig.internal.ConfigMetadataClient;
import com.google.firebase.remoteconfig.internal.ConfigStorageClient;
import com.google.firebase.remoteconfig.internal.LegacyConfigsHandler;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
/* JADX INFO: loaded from: classes.dex */
public class RemoteConfigComponent {
    public static final String ACTIVATE_FILE_NAME = "activate";
    public static final String DEFAULTS_FILE_NAME = "defaults";
    public static final String DEFAULT_NAMESPACE = "firebase";
    public static final String FETCH_FILE_NAME = "fetch";
    private static final String FIREBASE_REMOTE_CONFIG_FILE_NAME_PREFIX = "frc";
    public static final long NETWORK_CONNECTION_TIMEOUT_IN_SECONDS = 60;
    private static final String PREFERENCES_FILE_NAME = "settings";
    private final AnalyticsConnector analyticsConnector;
    private final String appId;
    private final Context context;
    private Map<String, String> customHeaders;
    private final ExecutorService executorService;
    private final FirebaseABTesting firebaseAbt;
    private final FirebaseApp firebaseApp;
    private final FirebaseInstanceId firebaseInstanceId;
    private final Map<String, FirebaseRemoteConfig> frcNamespaceInstances;
    private static final Clock DEFAULT_CLOCK = DefaultClock.getInstance();
    private static final Random DEFAULT_RANDOM = new Random();

    RemoteConfigComponent(Context context, FirebaseApp firebaseApp, FirebaseInstanceId firebaseInstanceId, FirebaseABTesting firebaseAbt, AnalyticsConnector analyticsConnector) {
        this(context, Executors.newCachedThreadPool(), firebaseApp, firebaseInstanceId, firebaseAbt, analyticsConnector, new LegacyConfigsHandler(context, firebaseApp.getOptions().getApplicationId()), true);
    }

    protected RemoteConfigComponent(Context context, ExecutorService executorService, FirebaseApp firebaseApp, FirebaseInstanceId firebaseInstanceId, FirebaseABTesting firebaseAbt, AnalyticsConnector analyticsConnector, LegacyConfigsHandler legacyConfigsHandler, boolean loadGetDefault) {
        this.frcNamespaceInstances = new HashMap();
        this.customHeaders = new HashMap();
        this.context = context;
        this.executorService = executorService;
        this.firebaseApp = firebaseApp;
        this.firebaseInstanceId = firebaseInstanceId;
        this.firebaseAbt = firebaseAbt;
        this.analyticsConnector = analyticsConnector;
        this.appId = firebaseApp.getOptions().getApplicationId();
        if (loadGetDefault) {
            Tasks.call(executorService, RemoteConfigComponent$$Lambda$1.lambdaFactory$(this));
            legacyConfigsHandler.getClass();
            Tasks.call(executorService, RemoteConfigComponent$$Lambda$4.lambdaFactory$(legacyConfigsHandler));
        }
    }

    FirebaseRemoteConfig getDefault() {
        return get(DEFAULT_NAMESPACE);
    }

    public synchronized FirebaseRemoteConfig get(String namespace) {
        ConfigCacheClient fetchedCacheClient;
        ConfigCacheClient activatedCacheClient;
        ConfigCacheClient defaultsCacheClient;
        ConfigMetadataClient metadataClient;
        fetchedCacheClient = getCacheClient(namespace, FETCH_FILE_NAME);
        activatedCacheClient = getCacheClient(namespace, ACTIVATE_FILE_NAME);
        defaultsCacheClient = getCacheClient(namespace, DEFAULTS_FILE_NAME);
        metadataClient = getMetadataClient(this.context, this.appId, namespace);
        return get(this.firebaseApp, namespace, this.firebaseAbt, this.executorService, fetchedCacheClient, activatedCacheClient, defaultsCacheClient, getFetchHandler(namespace, fetchedCacheClient, metadataClient), getGetHandler(activatedCacheClient, defaultsCacheClient), metadataClient);
    }

    synchronized FirebaseRemoteConfig get(FirebaseApp firebaseApp, String namespace, FirebaseABTesting firebaseAbt, Executor executor, ConfigCacheClient fetchedClient, ConfigCacheClient activatedClient, ConfigCacheClient defaultsClient, ConfigFetchHandler fetchHandler, ConfigGetParameterHandler getHandler, ConfigMetadataClient metadataClient) {
        if (!this.frcNamespaceInstances.containsKey(namespace)) {
            FirebaseRemoteConfig in = new FirebaseRemoteConfig(this.context, firebaseApp, isAbtSupported(firebaseApp, namespace) ? firebaseAbt : null, executor, fetchedClient, activatedClient, defaultsClient, fetchHandler, getHandler, metadataClient);
            in.startLoadingConfigsFromDisk();
            this.frcNamespaceInstances.put(namespace, in);
        }
        return this.frcNamespaceInstances.get(namespace);
    }

    public synchronized void setCustomHeaders(Map<String, String> customHeaders) {
        this.customHeaders = customHeaders;
    }

    private ConfigCacheClient getCacheClient(String namespace, String configStoreType) {
        return getCacheClient(this.context, this.appId, namespace, configStoreType);
    }

    public static ConfigCacheClient getCacheClient(Context context, String appId, String namespace, String configStoreType) {
        String fileName = String.format("%s_%s_%s_%s.json", "frc", appId, namespace, configStoreType);
        return ConfigCacheClient.getInstance(Executors.newCachedThreadPool(), ConfigStorageClient.getInstance(context, fileName));
    }

    ConfigFetchHttpClient getFrcBackendApiClient(String apiKey, String namespace, ConfigMetadataClient metadataClient) {
        String appId = this.firebaseApp.getOptions().getApplicationId();
        return new ConfigFetchHttpClient(this.context, appId, apiKey, namespace, metadataClient.getFetchTimeoutInSeconds(), 60L);
    }

    synchronized ConfigFetchHandler getFetchHandler(String namespace, ConfigCacheClient fetchedCacheClient, ConfigMetadataClient metadataClient) {
        return new ConfigFetchHandler(this.firebaseInstanceId, isPrimaryApp(this.firebaseApp) ? this.analyticsConnector : null, this.executorService, DEFAULT_CLOCK, DEFAULT_RANDOM, fetchedCacheClient, getFrcBackendApiClient(this.firebaseApp.getOptions().getApiKey(), namespace, metadataClient), metadataClient, this.customHeaders);
    }

    private ConfigGetParameterHandler getGetHandler(ConfigCacheClient activatedCacheClient, ConfigCacheClient defaultsCacheClient) {
        return new ConfigGetParameterHandler(activatedCacheClient, defaultsCacheClient);
    }

    static ConfigMetadataClient getMetadataClient(Context context, String appId, String namespace) {
        String fileName = String.format("%s_%s_%s_%s", "frc", appId, namespace, PREFERENCES_FILE_NAME);
        SharedPreferences preferences = context.getSharedPreferences(fileName, 0);
        return new ConfigMetadataClient(preferences);
    }

    private static boolean isAbtSupported(FirebaseApp firebaseApp, String namespace) {
        return namespace.equals(DEFAULT_NAMESPACE) && isPrimaryApp(firebaseApp);
    }

    private static boolean isPrimaryApp(FirebaseApp firebaseApp) {
        return firebaseApp.getName().equals(FirebaseApp.DEFAULT_APP_NAME);
    }
}
