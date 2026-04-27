package org.webrtc.mozi;

import android.util.Log;
import org.json.JSONException;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes3.dex */
public class StatsInfo {
    private static final String LOG_TAG = "McsStats";
    private JSONObject attrs;
    private final String module;

    public StatsInfo(String module, String attrs) {
        this.module = module;
        try {
            this.attrs = new JSONObject(attrs);
        } catch (JSONException e) {
            Log.e(LOG_TAG, "StatsInfo json error!");
        }
        if (this.attrs == null) {
            this.attrs = new JSONObject();
        }
    }

    public String getModule() {
        return this.module;
    }

    public JSONObject getAttrs() {
        return this.attrs;
    }

    static StatsInfo create(String module, String attrs) {
        return new StatsInfo(module, attrs);
    }
}
