package A1;

import com.facebook.react.bridge.WritableArray;

/* JADX INFO: loaded from: classes.dex */
public interface c {
    void callIdleCallbacks(double d3);

    void callTimers(WritableArray writableArray);

    void emitTimeDriftWarning(String str);
}
