package com.google.android.gms.vision;

import android.util.SparseArray;
import com.google.android.gms.vision.Detector;
import java.util.HashSet;
import java.util.Iterator;

/* JADX INFO: loaded from: classes.dex */
public class MultiProcessor<T> implements Detector.Processor<T> {
    private int zzal;
    private Factory<T> zzaz;
    private SparseArray<zza> zzba;

    public static class Builder<T> {
        private MultiProcessor<T> zzbb;

        public Builder(Factory<T> factory) {
            MultiProcessor<T> multiProcessor = new MultiProcessor<>();
            this.zzbb = multiProcessor;
            if (factory == null) {
                throw new IllegalArgumentException("No factory supplied.");
            }
            ((MultiProcessor) multiProcessor).zzaz = factory;
        }

        public MultiProcessor<T> build() {
            return this.zzbb;
        }

        public Builder<T> setMaxGapFrames(int i) {
            if (i >= 0) {
                ((MultiProcessor) this.zzbb).zzal = i;
                return this;
            }
            StringBuilder sb = new StringBuilder(28);
            sb.append("Invalid max gap: ");
            sb.append(i);
            throw new IllegalArgumentException(sb.toString());
        }
    }

    public interface Factory<T> {
        Tracker<T> create(T t);
    }

    class zza {
        private Tracker<T> zzak;
        private int zzao;

        private zza(MultiProcessor multiProcessor) {
            this.zzao = 0;
        }

        static /* synthetic */ int zza(zza zzaVar, int i) {
            zzaVar.zzao = 0;
            return 0;
        }

        static /* synthetic */ int zzb(zza zzaVar) {
            int i = zzaVar.zzao;
            zzaVar.zzao = i + 1;
            return i;
        }
    }

    private MultiProcessor() {
        this.zzba = new SparseArray<>();
        this.zzal = 3;
    }

    @Override // com.google.android.gms.vision.Detector.Processor
    public void receiveDetections(Detector.Detections<T> detections) {
        SparseArray<T> detectedItems = detections.getDetectedItems();
        for (int i = 0; i < detectedItems.size(); i++) {
            int iKeyAt = detectedItems.keyAt(i);
            T tValueAt = detectedItems.valueAt(i);
            if (this.zzba.get(iKeyAt) == null) {
                zza zzaVar = new zza();
                zzaVar.zzak = this.zzaz.create(tValueAt);
                zzaVar.zzak.onNewItem(iKeyAt, tValueAt);
                this.zzba.append(iKeyAt, zzaVar);
            }
        }
        SparseArray<T> detectedItems2 = detections.getDetectedItems();
        HashSet hashSet = new HashSet();
        for (int i2 = 0; i2 < this.zzba.size(); i2++) {
            int iKeyAt2 = this.zzba.keyAt(i2);
            if (detectedItems2.get(iKeyAt2) == null) {
                zza zzaVarValueAt = this.zzba.valueAt(i2);
                zza.zzb(zzaVarValueAt);
                if (zzaVarValueAt.zzao >= this.zzal) {
                    zzaVarValueAt.zzak.onDone();
                    hashSet.add(Integer.valueOf(iKeyAt2));
                } else {
                    zzaVarValueAt.zzak.onMissing(detections);
                }
            }
        }
        Iterator it = hashSet.iterator();
        while (it.hasNext()) {
            this.zzba.delete(((Integer) it.next()).intValue());
        }
        SparseArray<T> detectedItems3 = detections.getDetectedItems();
        for (int i3 = 0; i3 < detectedItems3.size(); i3++) {
            int iKeyAt3 = detectedItems3.keyAt(i3);
            T tValueAt2 = detectedItems3.valueAt(i3);
            zza zzaVar2 = this.zzba.get(iKeyAt3);
            zza.zza(zzaVar2, 0);
            zzaVar2.zzak.onUpdate(detections, tValueAt2);
        }
    }

    @Override // com.google.android.gms.vision.Detector.Processor
    public void release() {
        for (int i = 0; i < this.zzba.size(); i++) {
            this.zzba.valueAt(i).zzak.onDone();
        }
        this.zzba.clear();
    }
}
