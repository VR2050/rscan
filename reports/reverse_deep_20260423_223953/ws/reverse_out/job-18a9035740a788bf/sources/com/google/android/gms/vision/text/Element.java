package com.google.android.gms.vision.text;

import android.graphics.Point;
import android.graphics.Rect;
import com.google.android.gms.internal.vision.zzag;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public class Element implements Text {
    private zzag zzcy;

    Element(zzag zzagVar) {
        this.zzcy = zzagVar;
    }

    @Override // com.google.android.gms.vision.text.Text
    public Rect getBoundingBox() {
        return zzc.zza(this);
    }

    @Override // com.google.android.gms.vision.text.Text
    public List<? extends Text> getComponents() {
        return new ArrayList();
    }

    @Override // com.google.android.gms.vision.text.Text
    public Point[] getCornerPoints() {
        return zzc.zza(this.zzcy.zzdj);
    }

    public String getLanguage() {
        return this.zzcy.zzdd;
    }

    @Override // com.google.android.gms.vision.text.Text
    public String getValue() {
        return this.zzcy.zzdm;
    }
}
