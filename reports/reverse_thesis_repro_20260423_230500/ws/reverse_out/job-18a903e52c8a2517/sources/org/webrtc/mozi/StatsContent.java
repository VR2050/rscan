package org.webrtc.mozi;

import android.util.Log;
import org.json.JSONException;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes3.dex */
public class StatsContent {
    private static final String LOG_TAG = "McsStats";
    private JSONObject attrs;
    private JSONObject attrsWithoutSensitiveInfo;
    private final long date;
    private final String eventType;
    private final long level;
    private final String module;
    private final long timestamp;

    public StatsContent(long timestamp, long date, String module, String eventType, long level, JSONObject attrs) {
        this.timestamp = timestamp;
        this.date = date;
        this.module = module;
        this.eventType = eventType;
        this.level = level;
        this.attrs = attrs;
    }

    public StatsContent(long timestamp, long date, String module, String eventType, long level, String attrs) {
        this.timestamp = timestamp;
        this.date = date;
        this.module = module;
        this.eventType = eventType;
        this.level = level;
        try {
            this.attrs = new JSONObject(attrs);
        } catch (JSONException e) {
            Log.e(LOG_TAG, "StatsContent json error!");
        }
        if (this.attrs == null) {
            this.attrs = new JSONObject();
        }
    }

    public long getTimestamp() {
        return this.timestamp;
    }

    public long getDate() {
        return this.date;
    }

    public String getModule() {
        return this.module;
    }

    public String getEventType() {
        return this.eventType;
    }

    public long getLevel() {
        return this.level;
    }

    public JSONObject getAttrs() {
        return this.attrs;
    }

    public void setAttrsWithoutSensitiveInfo(JSONObject attrs) {
        this.attrsWithoutSensitiveInfo = attrs;
    }

    public JSONObject getAttrsWithoutSensitiveInfo() {
        JSONObject jSONObject = this.attrsWithoutSensitiveInfo;
        if (jSONObject == null) {
            return this.attrs;
        }
        return jSONObject;
    }

    static StatsContent create(long timestamp, long date, String module, String eventType, long level, String attrs) {
        return new StatsContent(timestamp, date, module, eventType, level, attrs);
    }
}
