package p005b.p199l.p200a.p201a.p246n1.p247h;

import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.opengl.Matrix;
import android.view.Display;
import androidx.annotation.BinderThread;
import p005b.p199l.p200a.p201a.p251q1.p252s.C2389c;

/* renamed from: b.l.a.a.n1.h.d */
/* loaded from: classes.dex */
public final class C2273d implements SensorEventListener {

    /* renamed from: a */
    public final float[] f5717a = new float[16];

    /* renamed from: b */
    public final float[] f5718b = new float[16];

    /* renamed from: c */
    public final float[] f5719c = new float[16];

    /* renamed from: d */
    public final float[] f5720d = new float[3];

    /* renamed from: e */
    public final Display f5721e;

    /* renamed from: f */
    public final a[] f5722f;

    /* renamed from: g */
    public boolean f5723g;

    /* renamed from: b.l.a.a.n1.h.d$a */
    public interface a {
        /* renamed from: a */
        void mo2172a(float[] fArr, float f2);
    }

    public C2273d(Display display, a... aVarArr) {
        this.f5721e = display;
        this.f5722f = aVarArr;
    }

    @Override // android.hardware.SensorEventListener
    public void onAccuracyChanged(Sensor sensor, int i2) {
    }

    @Override // android.hardware.SensorEventListener
    @BinderThread
    public void onSensorChanged(SensorEvent sensorEvent) {
        SensorManager.getRotationMatrixFromVector(this.f5717a, sensorEvent.values);
        float[] fArr = this.f5717a;
        int rotation = this.f5721e.getRotation();
        if (rotation != 0) {
            int i2 = 129;
            int i3 = 130;
            if (rotation == 1) {
                i2 = 2;
                i3 = 129;
            } else if (rotation != 2) {
                if (rotation != 3) {
                    throw new IllegalStateException();
                }
                i2 = 130;
                i3 = 1;
            }
            float[] fArr2 = this.f5718b;
            System.arraycopy(fArr, 0, fArr2, 0, fArr2.length);
            SensorManager.remapCoordinateSystem(this.f5718b, i2, i3, fArr);
        }
        SensorManager.remapCoordinateSystem(this.f5717a, 1, 131, this.f5718b);
        SensorManager.getOrientation(this.f5718b, this.f5720d);
        float f2 = this.f5720d[2];
        Matrix.rotateM(this.f5717a, 0, 90.0f, 1.0f, 0.0f, 0.0f);
        float[] fArr3 = this.f5717a;
        if (!this.f5723g) {
            C2389c.m2643a(this.f5719c, fArr3);
            this.f5723g = true;
        }
        float[] fArr4 = this.f5718b;
        System.arraycopy(fArr3, 0, fArr4, 0, fArr4.length);
        Matrix.multiplyMM(fArr3, 0, this.f5718b, 0, this.f5719c, 0);
        float[] fArr5 = this.f5717a;
        for (a aVar : this.f5722f) {
            aVar.mo2172a(fArr5, f2);
        }
    }
}
