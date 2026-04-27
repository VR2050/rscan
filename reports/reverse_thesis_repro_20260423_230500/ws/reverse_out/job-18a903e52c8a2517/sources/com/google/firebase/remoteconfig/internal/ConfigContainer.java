package com.google.firebase.remoteconfig.internal;

import java.util.Date;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
/* JADX INFO: loaded from: classes.dex */
public class ConfigContainer {
    private static final String ABT_EXPERIMENTS_KEY = "abt_experiments_key";
    private static final String CONFIGS_KEY = "configs_key";
    private static final Date DEFAULTS_FETCH_TIME = new Date(0);
    private static final String FETCH_TIME_KEY = "fetch_time_key";
    private JSONArray abtExperiments;
    private JSONObject configsJson;
    private JSONObject containerJson;
    private Date fetchTime;

    private ConfigContainer(JSONObject configsJson, Date fetchTime, JSONArray abtExperiments) throws JSONException {
        JSONObject containerJson = new JSONObject();
        containerJson.put(CONFIGS_KEY, configsJson);
        containerJson.put(FETCH_TIME_KEY, fetchTime.getTime());
        containerJson.put(ABT_EXPERIMENTS_KEY, abtExperiments);
        this.configsJson = configsJson;
        this.fetchTime = fetchTime;
        this.abtExperiments = abtExperiments;
        this.containerJson = containerJson;
    }

    static ConfigContainer copyOf(JSONObject containerJson) throws JSONException {
        return new ConfigContainer(containerJson.getJSONObject(CONFIGS_KEY), new Date(containerJson.getLong(FETCH_TIME_KEY)), containerJson.getJSONArray(ABT_EXPERIMENTS_KEY));
    }

    public JSONObject getConfigs() {
        return this.configsJson;
    }

    public Date getFetchTime() {
        return this.fetchTime;
    }

    public JSONArray getAbtExperiments() {
        return this.abtExperiments;
    }

    public String toString() {
        return this.containerJson.toString();
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ConfigContainer)) {
            return false;
        }
        ConfigContainer that = (ConfigContainer) o;
        return this.containerJson.toString().equals(that.toString());
    }

    public int hashCode() {
        return this.containerJson.hashCode();
    }

    /* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
    public static class Builder {
        private JSONArray builderAbtExperiments;
        private JSONObject builderConfigsJson;
        private Date builderFetchTime;

        private Builder() {
            this.builderConfigsJson = new JSONObject();
            this.builderFetchTime = ConfigContainer.DEFAULTS_FETCH_TIME;
            this.builderAbtExperiments = new JSONArray();
        }

        public Builder(ConfigContainer otherContainer) {
            this.builderConfigsJson = otherContainer.getConfigs();
            this.builderFetchTime = otherContainer.getFetchTime();
            this.builderAbtExperiments = otherContainer.getAbtExperiments();
        }

        public Builder replaceConfigsWith(Map<String, String> configsMap) {
            this.builderConfigsJson = new JSONObject(configsMap);
            return this;
        }

        public Builder replaceConfigsWith(JSONObject configsJson) {
            try {
                this.builderConfigsJson = new JSONObject(configsJson.toString());
            } catch (JSONException e) {
            }
            return this;
        }

        public Builder withFetchTime(Date fetchTime) {
            this.builderFetchTime = fetchTime;
            return this;
        }

        public Builder withAbtExperiments(JSONArray abtExperiments) {
            try {
                this.builderAbtExperiments = new JSONArray(abtExperiments.toString());
            } catch (JSONException e) {
            }
            return this;
        }

        public ConfigContainer build() throws JSONException {
            return new ConfigContainer(this.builderConfigsJson, this.builderFetchTime, this.builderAbtExperiments);
        }
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    public static Builder newBuilder(ConfigContainer otherContainer) {
        return new Builder(otherContainer);
    }
}
