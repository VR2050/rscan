package com.google.firebase.remoteconfig;

import android.content.Context;
import android.util.Log;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.Tasks;
import com.google.firebase.FirebaseApp;
import com.google.firebase.abt.AbtException;
import com.google.firebase.abt.FirebaseABTesting;
import com.google.firebase.remoteconfig.internal.ConfigCacheClient;
import com.google.firebase.remoteconfig.internal.ConfigContainer;
import com.google.firebase.remoteconfig.internal.ConfigFetchHandler;
import com.google.firebase.remoteconfig.internal.ConfigGetParameterHandler;
import com.google.firebase.remoteconfig.internal.ConfigMetadataClient;
import com.google.firebase.remoteconfig.internal.DefaultsXmlParser;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executor;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
/* JADX INFO: loaded from: classes.dex */
public class FirebaseRemoteConfig {
    public static final boolean DEFAULT_VALUE_FOR_BOOLEAN = false;
    public static final byte[] DEFAULT_VALUE_FOR_BYTE_ARRAY = new byte[0];
    public static final double DEFAULT_VALUE_FOR_DOUBLE = 0.0d;
    public static final long DEFAULT_VALUE_FOR_LONG = 0;
    public static final String DEFAULT_VALUE_FOR_STRING = "";
    public static final int LAST_FETCH_STATUS_FAILURE = 1;
    public static final int LAST_FETCH_STATUS_NO_FETCH_YET = 0;
    public static final int LAST_FETCH_STATUS_SUCCESS = -1;
    public static final int LAST_FETCH_STATUS_THROTTLED = 2;
    public static final String TAG = "FirebaseRemoteConfig";
    public static final int VALUE_SOURCE_DEFAULT = 1;
    public static final int VALUE_SOURCE_REMOTE = 2;
    public static final int VALUE_SOURCE_STATIC = 0;
    private final ConfigCacheClient activatedConfigsCache;
    private final Context context;
    private final ConfigCacheClient defaultConfigsCache;
    private final Executor executor;
    private final ConfigFetchHandler fetchHandler;
    private final ConfigCacheClient fetchedConfigsCache;
    private final FirebaseABTesting firebaseAbt;
    private final FirebaseApp firebaseApp;
    private final ConfigMetadataClient frcMetadata;
    private final ConfigGetParameterHandler getHandler;

    public static FirebaseRemoteConfig getInstance() {
        return getInstance(FirebaseApp.getInstance());
    }

    public static FirebaseRemoteConfig getInstance(FirebaseApp app) {
        return ((RemoteConfigComponent) app.get(RemoteConfigComponent.class)).getDefault();
    }

    FirebaseRemoteConfig(Context context, FirebaseApp firebaseApp, FirebaseABTesting firebaseAbt, Executor executor, ConfigCacheClient fetchedConfigsCache, ConfigCacheClient activatedConfigsCache, ConfigCacheClient defaultConfigsCache, ConfigFetchHandler fetchHandler, ConfigGetParameterHandler getHandler, ConfigMetadataClient frcMetadata) {
        this.context = context;
        this.firebaseApp = firebaseApp;
        this.firebaseAbt = firebaseAbt;
        this.executor = executor;
        this.fetchedConfigsCache = fetchedConfigsCache;
        this.activatedConfigsCache = activatedConfigsCache;
        this.defaultConfigsCache = defaultConfigsCache;
        this.fetchHandler = fetchHandler;
        this.getHandler = getHandler;
        this.frcMetadata = frcMetadata;
    }

    public Task<FirebaseRemoteConfigInfo> ensureInitialized() {
        Task<ConfigContainer> activatedConfigsTask = this.activatedConfigsCache.get();
        Task<ConfigContainer> defaultsConfigsTask = this.defaultConfigsCache.get();
        Task<ConfigContainer> fetchedConfigsTask = this.fetchedConfigsCache.get();
        Task<FirebaseRemoteConfigInfo> metadataTask = Tasks.call(this.executor, FirebaseRemoteConfig$$Lambda$1.lambdaFactory$(this));
        return Tasks.whenAllComplete((Task<?>[]) new Task[]{activatedConfigsTask, defaultsConfigsTask, fetchedConfigsTask, metadataTask}).continueWith(this.executor, FirebaseRemoteConfig$$Lambda$2.lambdaFactory$(metadataTask));
    }

    static /* synthetic */ FirebaseRemoteConfigInfo lambda$ensureInitialized$0(Task metadataTask, Task unusedListOfCompletedTasks) throws Exception {
        return (FirebaseRemoteConfigInfo) metadataTask.getResult();
    }

    static /* synthetic */ Task lambda$fetchAndActivate$1(FirebaseRemoteConfig firebaseRemoteConfig, Void unusedVoid) throws Exception {
        return firebaseRemoteConfig.activate();
    }

    public Task<Boolean> fetchAndActivate() {
        return fetch().onSuccessTask(this.executor, FirebaseRemoteConfig$$Lambda$3.lambdaFactory$(this));
    }

    @Deprecated
    public boolean activateFetched() {
        ConfigContainer fetchedContainer = this.fetchedConfigsCache.getBlocking();
        if (fetchedContainer == null) {
            return false;
        }
        ConfigContainer activatedContainer = this.activatedConfigsCache.getBlocking();
        if (!isFetchedFresh(fetchedContainer, activatedContainer)) {
            return false;
        }
        this.activatedConfigsCache.putWithoutWaitingForDiskWrite(fetchedContainer).addOnSuccessListener(this.executor, FirebaseRemoteConfig$$Lambda$4.lambdaFactory$(this));
        return true;
    }

    static /* synthetic */ void lambda$activateFetched$2(FirebaseRemoteConfig firebaseRemoteConfig, ConfigContainer newlyActivatedContainer) {
        firebaseRemoteConfig.fetchedConfigsCache.clear();
        firebaseRemoteConfig.updateAbtWithActivatedExperiments(newlyActivatedContainer.getAbtExperiments());
    }

    public Task<Boolean> activate() {
        Task<ConfigContainer> fetchedConfigsTask = this.fetchedConfigsCache.get();
        Task<ConfigContainer> activatedConfigsTask = this.activatedConfigsCache.get();
        return Tasks.whenAllComplete((Task<?>[]) new Task[]{fetchedConfigsTask, activatedConfigsTask}).continueWithTask(this.executor, FirebaseRemoteConfig$$Lambda$5.lambdaFactory$(this, fetchedConfigsTask, activatedConfigsTask));
    }

    static /* synthetic */ Task lambda$activate$3(FirebaseRemoteConfig firebaseRemoteConfig, Task fetchedConfigsTask, Task activatedConfigsTask, Task unusedListOfCompletedTasks) throws Exception {
        if (!fetchedConfigsTask.isSuccessful() || fetchedConfigsTask.getResult() == null) {
            return Tasks.forResult(false);
        }
        ConfigContainer fetchedContainer = (ConfigContainer) fetchedConfigsTask.getResult();
        if (activatedConfigsTask.isSuccessful()) {
            ConfigContainer activatedContainer = (ConfigContainer) activatedConfigsTask.getResult();
            if (!isFetchedFresh(fetchedContainer, activatedContainer)) {
                return Tasks.forResult(false);
            }
        }
        return firebaseRemoteConfig.activatedConfigsCache.put(fetchedContainer).continueWith(firebaseRemoteConfig.executor, FirebaseRemoteConfig$$Lambda$11.lambdaFactory$(firebaseRemoteConfig));
    }

    public Task<Void> fetch() {
        Task<ConfigFetchHandler.FetchResponse> fetchTask = this.fetchHandler.fetch();
        return fetchTask.onSuccessTask(FirebaseRemoteConfig$$Lambda$6.instance);
    }

    static /* synthetic */ Task lambda$fetch$4(ConfigFetchHandler.FetchResponse unusedFetchResponse) throws Exception {
        return Tasks.forResult(null);
    }

    public Task<Void> fetch(long minimumFetchIntervalInSeconds) {
        Task<ConfigFetchHandler.FetchResponse> fetchTask = this.fetchHandler.fetch(minimumFetchIntervalInSeconds);
        return fetchTask.onSuccessTask(FirebaseRemoteConfig$$Lambda$7.instance);
    }

    static /* synthetic */ Task lambda$fetch$5(ConfigFetchHandler.FetchResponse unusedFetchResponse) throws Exception {
        return Tasks.forResult(null);
    }

    public String getString(String key) {
        return this.getHandler.getString(key);
    }

    public boolean getBoolean(String key) {
        return this.getHandler.getBoolean(key);
    }

    @Deprecated
    public byte[] getByteArray(String key) {
        return this.getHandler.getByteArray(key);
    }

    public double getDouble(String key) {
        return this.getHandler.getDouble(key);
    }

    public long getLong(String key) {
        return this.getHandler.getLong(key);
    }

    public FirebaseRemoteConfigValue getValue(String key) {
        return this.getHandler.getValue(key);
    }

    public Set<String> getKeysByPrefix(String prefix) {
        return this.getHandler.getKeysByPrefix(prefix);
    }

    public Map<String, FirebaseRemoteConfigValue> getAll() {
        return this.getHandler.getAll();
    }

    public FirebaseRemoteConfigInfo getInfo() {
        return this.frcMetadata.getInfo();
    }

    @Deprecated
    public void setConfigSettings(FirebaseRemoteConfigSettings settings) {
        this.frcMetadata.setConfigSettingsWithoutWaitingOnDiskWrite(settings);
    }

    public Task<Void> setConfigSettingsAsync(FirebaseRemoteConfigSettings settings) {
        return Tasks.call(this.executor, FirebaseRemoteConfig$$Lambda$8.lambdaFactory$(this, settings));
    }

    static /* synthetic */ Void lambda$setConfigSettingsAsync$6(FirebaseRemoteConfig firebaseRemoteConfig, FirebaseRemoteConfigSettings settings) throws Exception {
        firebaseRemoteConfig.frcMetadata.setConfigSettings(settings);
        return null;
    }

    @Deprecated
    public void setDefaults(Map<String, Object> defaults) {
        Map<String, String> defaultsStringMap = new HashMap<>();
        for (Map.Entry<String, Object> defaultsEntry : defaults.entrySet()) {
            Object value = defaultsEntry.getValue();
            if (value instanceof byte[]) {
                defaultsStringMap.put(defaultsEntry.getKey(), new String((byte[]) value));
            } else {
                defaultsStringMap.put(defaultsEntry.getKey(), value.toString());
            }
        }
        setDefaultsWithStringsMap(defaultsStringMap);
    }

    public Task<Void> setDefaultsAsync(Map<String, Object> defaults) {
        Map<String, String> defaultsStringMap = new HashMap<>();
        for (Map.Entry<String, Object> defaultsEntry : defaults.entrySet()) {
            Object value = defaultsEntry.getValue();
            if (value instanceof byte[]) {
                defaultsStringMap.put(defaultsEntry.getKey(), new String((byte[]) value));
            } else {
                defaultsStringMap.put(defaultsEntry.getKey(), value.toString());
            }
        }
        return setDefaultsWithStringsMapAsync(defaultsStringMap);
    }

    @Deprecated
    public void setDefaults(int resourceId) {
        Map<String, String> xmlDefaults = DefaultsXmlParser.getDefaultsFromXml(this.context, resourceId);
        setDefaultsWithStringsMap(xmlDefaults);
    }

    public Task<Void> setDefaultsAsync(int resourceId) {
        Map<String, String> xmlDefaults = DefaultsXmlParser.getDefaultsFromXml(this.context, resourceId);
        return setDefaultsWithStringsMapAsync(xmlDefaults);
    }

    public Task<Void> reset() {
        return Tasks.call(this.executor, FirebaseRemoteConfig$$Lambda$9.lambdaFactory$(this));
    }

    static /* synthetic */ Void lambda$reset$7(FirebaseRemoteConfig firebaseRemoteConfig) throws Exception {
        firebaseRemoteConfig.activatedConfigsCache.clear();
        firebaseRemoteConfig.fetchedConfigsCache.clear();
        firebaseRemoteConfig.defaultConfigsCache.clear();
        firebaseRemoteConfig.frcMetadata.clear();
        return null;
    }

    void startLoadingConfigsFromDisk() {
        this.activatedConfigsCache.get();
        this.defaultConfigsCache.get();
        this.fetchedConfigsCache.get();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean processActivatePutTask(Task<ConfigContainer> putTask) {
        if (putTask.isSuccessful()) {
            this.fetchedConfigsCache.clear();
            if (putTask.getResult() != null) {
                updateAbtWithActivatedExperiments(putTask.getResult().getAbtExperiments());
                return true;
            }
            Log.e(TAG, "Activated configs written to disk are null.");
            return true;
        }
        return false;
    }

    private void setDefaultsWithStringsMap(Map<String, String> defaultsStringMap) {
        try {
            ConfigContainer defaultConfigs = ConfigContainer.newBuilder().replaceConfigsWith(defaultsStringMap).build();
            this.defaultConfigsCache.putWithoutWaitingForDiskWrite(defaultConfigs);
        } catch (JSONException e) {
            Log.e(TAG, "The provided defaults map could not be processed.", e);
        }
    }

    private Task<Void> setDefaultsWithStringsMapAsync(Map<String, String> defaultsStringMap) {
        try {
            ConfigContainer defaultConfigs = ConfigContainer.newBuilder().replaceConfigsWith(defaultsStringMap).build();
            Task<ConfigContainer> putTask = this.defaultConfigsCache.put(defaultConfigs);
            return putTask.onSuccessTask(FirebaseRemoteConfig$$Lambda$10.instance);
        } catch (JSONException e) {
            Log.e(TAG, "The provided defaults map could not be processed.", e);
            return Tasks.forResult(null);
        }
    }

    static /* synthetic */ Task lambda$setDefaultsWithStringsMapAsync$8(ConfigContainer unusedContainer) throws Exception {
        return Tasks.forResult(null);
    }

    void updateAbtWithActivatedExperiments(JSONArray abtExperiments) {
        if (this.firebaseAbt == null) {
            return;
        }
        try {
            List<Map<String, String>> experimentInfoMaps = toExperimentInfoMaps(abtExperiments);
            this.firebaseAbt.replaceAllExperiments(experimentInfoMaps);
        } catch (AbtException e) {
            Log.w(TAG, "Could not update ABT experiments.", e);
        } catch (JSONException e2) {
            Log.e(TAG, "Could not parse ABT experiments from the JSON response.", e2);
        }
    }

    static List<Map<String, String>> toExperimentInfoMaps(JSONArray abtExperimentsJson) throws JSONException {
        List<Map<String, String>> experimentInfoMaps = new ArrayList<>();
        for (int index = 0; index < abtExperimentsJson.length(); index++) {
            Map<String, String> experimentInfo = new HashMap<>();
            JSONObject abtExperimentJson = abtExperimentsJson.getJSONObject(index);
            Iterator<String> experimentJsonKeyIterator = abtExperimentJson.keys();
            while (experimentJsonKeyIterator.hasNext()) {
                String key = experimentJsonKeyIterator.next();
                experimentInfo.put(key, abtExperimentJson.getString(key));
            }
            experimentInfoMaps.add(experimentInfo);
        }
        return experimentInfoMaps;
    }

    private static boolean isFetchedFresh(ConfigContainer fetched, ConfigContainer activated) {
        return activated == null || !fetched.getFetchTime().equals(activated.getFetchTime());
    }
}
