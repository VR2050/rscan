package com.king.zxing;

import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.preference.PreferenceManager;
import com.king.zxing.camera.CameraManager;
import com.king.zxing.camera.FrontLightMode;

/* JADX INFO: loaded from: classes3.dex */
final class AmbientLightManager implements SensorEventListener {
    protected static final float BRIGHT_ENOUGH_LUX = 100.0f;
    protected static final float TOO_DARK_LUX = 45.0f;
    private CameraManager cameraManager;
    private final Context context;
    private Sensor lightSensor;
    private float tooDarkLux = TOO_DARK_LUX;
    private float brightEnoughLux = BRIGHT_ENOUGH_LUX;

    AmbientLightManager(Context context) {
        this.context = context;
    }

    void start(CameraManager cameraManager) {
        this.cameraManager = cameraManager;
        SharedPreferences sharedPrefs = PreferenceManager.getDefaultSharedPreferences(this.context);
        if (FrontLightMode.readPref(sharedPrefs) == FrontLightMode.AUTO) {
            SensorManager sensorManager = (SensorManager) this.context.getSystemService("sensor");
            Sensor defaultSensor = sensorManager.getDefaultSensor(5);
            this.lightSensor = defaultSensor;
            if (defaultSensor != null) {
                sensorManager.registerListener(this, defaultSensor, 3);
            }
        }
    }

    void stop() {
        if (this.lightSensor != null) {
            SensorManager sensorManager = (SensorManager) this.context.getSystemService("sensor");
            sensorManager.unregisterListener(this);
            this.cameraManager = null;
            this.lightSensor = null;
        }
    }

    @Override // android.hardware.SensorEventListener
    public void onSensorChanged(SensorEvent sensorEvent) {
        float ambientLightLux = sensorEvent.values[0];
        CameraManager cameraManager = this.cameraManager;
        if (cameraManager != null) {
            if (ambientLightLux <= this.tooDarkLux) {
                cameraManager.sensorChanged(true, ambientLightLux);
            } else if (ambientLightLux >= this.brightEnoughLux) {
                cameraManager.sensorChanged(false, ambientLightLux);
            }
        }
    }

    public void setTooDarkLux(float tooDarkLux) {
        this.tooDarkLux = tooDarkLux;
    }

    public void setBrightEnoughLux(float brightEnoughLux) {
        this.brightEnoughLux = brightEnoughLux;
    }

    @Override // android.hardware.SensorEventListener
    public void onAccuracyChanged(Sensor sensor, int accuracy) {
    }
}
