package im.uwrkaxlmjj.keepalive;

import android.app.Activity;
import android.os.Build;
import android.os.Bundle;
import android.os.PowerManager;
import android.view.MotionEvent;
import android.view.Window;
import android.view.WindowManager;
import im.uwrkaxlmjj.messenger.FileLog;
import java.lang.ref.WeakReference;

/* JADX INFO: loaded from: classes2.dex */
public class OnePxActivity extends Activity {
    public static WeakReference<OnePxActivity> instance;

    @Override // android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        instance = new WeakReference<>(this);
        try {
            Window window = getWindow();
            if (window != null) {
                window.setGravity(51);
                WindowManager.LayoutParams attributes = window.getAttributes();
                if (attributes != null) {
                    attributes.x = 0;
                    attributes.y = 0;
                    attributes.height = 1;
                    attributes.width = 1;
                    window.setAttributes(attributes);
                }
            }
        } catch (Throwable e) {
            FileLog.e("OnePxActivity onCreate error:" + e.toString());
        }
    }

    @Override // android.app.Activity
    protected void onResume() {
        super.onResume();
        if (isScreenOn()) {
            finishSelf();
        }
    }

    @Override // android.app.Activity
    protected void onDestroy() {
        super.onDestroy();
        WeakReference<OnePxActivity> weakReference = instance;
        if (weakReference != null && weakReference.get() == this) {
            instance = null;
        }
    }

    public void finishSelf() {
        try {
            if (!isFinishing()) {
                finish();
            }
        } catch (Throwable e) {
            FileLog.e("OnePxActivity finishSelf error:" + e.toString());
        }
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public boolean dispatchTouchEvent(MotionEvent motionEvent) {
        finishSelf();
        return super.dispatchTouchEvent(motionEvent);
    }

    @Override // android.app.Activity
    public boolean onTouchEvent(MotionEvent motionEvent) {
        finishSelf();
        return super.onTouchEvent(motionEvent);
    }

    private boolean isScreenOn() {
        try {
            PowerManager powerManager = (PowerManager) getSystemService("power");
            if (Build.VERSION.SDK_INT >= 20) {
                return powerManager.isInteractive();
            }
            return powerManager.isScreenOn();
        } catch (Throwable e) {
            FileLog.e("OnePxActivity isScreenOn error:" + e.toString());
            return false;
        }
    }
}
