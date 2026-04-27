package com.google.android.gms.vision;

import android.util.Log;
import android.util.SparseArray;
import com.google.android.gms.vision.Detector;

/* JADX INFO: loaded from: classes.dex */
public abstract class FocusingProcessor<T> implements Detector.Processor<T> {
    private Tracker<T> zzak;
    private int zzan;
    private Detector<T> zzr;
    private int zzal = 3;
    private boolean zzam = false;
    private int zzao = 0;

    public FocusingProcessor(Detector<T> detector, Tracker<T> tracker) {
        this.zzr = detector;
        this.zzak = tracker;
    }

    @Override // com.google.android.gms.vision.Detector.Processor
    public void receiveDetections(Detector.Detections<T> detections) {
        SparseArray<T> detectedItems = detections.getDetectedItems();
        if (detectedItems.size() == 0) {
            if (this.zzao == this.zzal) {
                this.zzak.onDone();
                this.zzam = false;
            } else {
                this.zzak.onMissing(detections);
            }
            this.zzao++;
            return;
        }
        this.zzao = 0;
        if (this.zzam) {
            T t = detectedItems.get(this.zzan);
            if (t != null) {
                this.zzak.onUpdate(detections, t);
                return;
            } else {
                this.zzak.onDone();
                this.zzam = false;
            }
        }
        int iSelectFocus = selectFocus(detections);
        T t2 = detectedItems.get(iSelectFocus);
        if (t2 == null) {
            StringBuilder sb = new StringBuilder(35);
            sb.append("Invalid focus selected: ");
            sb.append(iSelectFocus);
            Log.w("FocusingProcessor", sb.toString());
            return;
        }
        this.zzam = true;
        this.zzan = iSelectFocus;
        this.zzr.setFocus(iSelectFocus);
        this.zzak.onNewItem(this.zzan, t2);
        this.zzak.onUpdate(detections, t2);
    }

    @Override // com.google.android.gms.vision.Detector.Processor
    public void release() {
        this.zzak.onDone();
    }

    public abstract int selectFocus(Detector.Detections<T> detections);

    protected final void zza(int i) {
        if (i >= 0) {
            this.zzal = i;
            return;
        }
        StringBuilder sb = new StringBuilder(28);
        sb.append("Invalid max gap: ");
        sb.append(i);
        throw new IllegalArgumentException(sb.toString());
    }
}
