package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.view.WindowManager;
import im.uwrkaxlmjj.messenger.AndroidUtilities;

/* JADX INFO: loaded from: classes5.dex */
public class WallpaperParallaxEffect implements SensorEventListener {
    private Sensor accelerometer;
    private int bufferOffset;
    private Callback callback;
    private boolean enabled;
    private SensorManager sensorManager;
    private WindowManager wm;
    private float[] rollBuffer = new float[3];
    private float[] pitchBuffer = new float[3];

    public interface Callback {
        void onOffsetsChanged(int i, int i2);
    }

    public WallpaperParallaxEffect(Context context) {
        this.wm = (WindowManager) context.getSystemService("window");
        SensorManager sensorManager = (SensorManager) context.getSystemService("sensor");
        this.sensorManager = sensorManager;
        this.accelerometer = sensorManager.getDefaultSensor(1);
    }

    public void setEnabled(boolean enabled) {
        if (this.enabled != enabled) {
            this.enabled = enabled;
            Sensor sensor = this.accelerometer;
            if (sensor == null) {
                return;
            }
            if (enabled) {
                this.sensorManager.registerListener(this, sensor, 1);
            } else {
                this.sensorManager.unregisterListener(this);
            }
        }
    }

    public void setCallback(Callback callback) {
        this.callback = callback;
    }

    public float getScale(int boundsWidth, int boundsHeight) {
        int offset = AndroidUtilities.dp(16.0f);
        return Math.max((boundsWidth + (offset * 2)) / boundsWidth, (boundsHeight + (offset * 2)) / boundsHeight);
    }

    @Override // android.hardware.SensorEventListener
    public void onSensorChanged(SensorEvent event) {
        float[] fArr;
        int rotation = this.wm.getDefaultDisplay().getRotation();
        float x = event.values[0] / 9.80665f;
        float y = event.values[1] / 9.80665f;
        float z = event.values[2] / 9.80665f;
        float pitch = (float) ((Math.atan2(x, Math.sqrt((y * y) + (z * z))) / 3.141592653589793d) * 2.0d);
        float roll = (float) ((Math.atan2(y, Math.sqrt((x * x) + (z * z))) / 3.141592653589793d) * 2.0d);
        if (rotation == 1) {
            pitch = roll;
            roll = pitch;
        } else if (rotation == 2) {
            roll = -roll;
            pitch = -pitch;
        } else if (rotation == 3) {
            float tmp = -pitch;
            pitch = roll;
            roll = tmp;
        }
        float[] fArr2 = this.rollBuffer;
        int i = this.bufferOffset;
        fArr2[i] = roll;
        this.pitchBuffer[i] = pitch;
        this.bufferOffset = (i + 1) % fArr2.length;
        float pitch2 = 0.0f;
        float roll2 = 0.0f;
        int i2 = 0;
        while (true) {
            fArr = this.rollBuffer;
            if (i2 >= fArr.length) {
                break;
            }
            roll2 += fArr[i2];
            pitch2 += this.pitchBuffer[i2];
            i2++;
        }
        int i3 = fArr.length;
        float roll3 = roll2 / i3;
        float pitch3 = pitch2 / fArr.length;
        if (roll3 > 1.0f) {
            roll3 = 2.0f - roll3;
        } else if (roll3 < -1.0f) {
            roll3 = (-2.0f) - roll3;
        }
        int offsetX = Math.round(AndroidUtilities.dpf2(16.0f) * pitch3);
        int offsetY = Math.round(AndroidUtilities.dpf2(16.0f) * roll3);
        Callback callback = this.callback;
        if (callback != null) {
            callback.onOffsetsChanged(offsetX, offsetY);
        }
    }

    @Override // android.hardware.SensorEventListener
    public void onAccuracyChanged(Sensor sensor, int accuracy) {
    }
}
