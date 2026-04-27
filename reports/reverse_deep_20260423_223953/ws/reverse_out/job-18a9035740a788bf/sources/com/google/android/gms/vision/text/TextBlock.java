package com.google.android.gms.vision.text;

import android.graphics.Point;
import android.graphics.Rect;
import android.util.SparseArray;
import com.google.android.exoplayer2.C;
import com.google.android.gms.internal.vision.zzr;
import com.google.android.gms.internal.vision.zzx;
import com.snail.antifake.deviceid.ShellAdbUtils;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public class TextBlock implements Text {
    private Point[] cornerPoints;
    private zzx[] zzdb;
    private List<Line> zzdc;
    private String zzdd;
    private Rect zzde;

    TextBlock(SparseArray<zzx> sparseArray) {
        this.zzdb = new zzx[sparseArray.size()];
        int i = 0;
        while (true) {
            zzx[] zzxVarArr = this.zzdb;
            if (i >= zzxVarArr.length) {
                return;
            }
            zzxVarArr[i] = sparseArray.valueAt(i);
            i++;
        }
    }

    @Override // com.google.android.gms.vision.text.Text
    public Rect getBoundingBox() {
        if (this.zzde == null) {
            this.zzde = zzc.zza(this);
        }
        return this.zzde;
    }

    @Override // com.google.android.gms.vision.text.Text
    public List<? extends Text> getComponents() {
        if (this.zzdb.length == 0) {
            return new ArrayList(0);
        }
        if (this.zzdc == null) {
            this.zzdc = new ArrayList(this.zzdb.length);
            for (zzx zzxVar : this.zzdb) {
                this.zzdc.add(new Line(zzxVar));
            }
        }
        return this.zzdc;
    }

    @Override // com.google.android.gms.vision.text.Text
    public Point[] getCornerPoints() {
        TextBlock textBlock;
        zzx[] zzxVarArr;
        TextBlock textBlock2 = this;
        if (textBlock2.cornerPoints == null) {
            char c = 0;
            if (textBlock2.zzdb.length == 0) {
                textBlock2.cornerPoints = new Point[0];
                textBlock = textBlock2;
            } else {
                int iMax = Integer.MIN_VALUE;
                int iMax2 = Integer.MIN_VALUE;
                int iMin = Integer.MAX_VALUE;
                int iMin2 = Integer.MAX_VALUE;
                int i = 0;
                while (true) {
                    zzxVarArr = textBlock2.zzdb;
                    if (i >= zzxVarArr.length) {
                        break;
                    }
                    zzr zzrVar = zzxVarArr[i].zzdj;
                    zzr zzrVar2 = textBlock2.zzdb[c].zzdj;
                    int i2 = -zzrVar2.left;
                    int i3 = -zzrVar2.top;
                    double dSin = Math.sin(Math.toRadians(zzrVar2.zzdh));
                    double dCos = Math.cos(Math.toRadians(zzrVar2.zzdh));
                    Point[] pointArr = new Point[4];
                    pointArr[c] = new Point(zzrVar.left, zzrVar.top);
                    pointArr[c].offset(i2, i3);
                    int i4 = iMax2;
                    int i5 = (int) ((((double) pointArr[c].x) * dCos) + (((double) pointArr[c].y) * dSin));
                    int i6 = (int) ((((double) (-pointArr[0].x)) * dSin) + (((double) pointArr[0].y) * dCos));
                    pointArr[0].x = i5;
                    pointArr[0].y = i6;
                    pointArr[1] = new Point(zzrVar.width + i5, i6);
                    pointArr[2] = new Point(zzrVar.width + i5, zzrVar.height + i6);
                    pointArr[3] = new Point(i5, i6 + zzrVar.height);
                    iMax2 = i4;
                    for (int i7 = 0; i7 < 4; i7++) {
                        Point point = pointArr[i7];
                        iMin = Math.min(iMin, point.x);
                        iMax = Math.max(iMax, point.x);
                        iMin2 = Math.min(iMin2, point.y);
                        iMax2 = Math.max(iMax2, point.y);
                    }
                    i++;
                    c = 0;
                    textBlock2 = this;
                }
                int i8 = iMax2;
                zzr zzrVar3 = zzxVarArr[0].zzdj;
                int i9 = zzrVar3.left;
                int i10 = zzrVar3.top;
                double dSin2 = Math.sin(Math.toRadians(zzrVar3.zzdh));
                double dCos2 = Math.cos(Math.toRadians(zzrVar3.zzdh));
                Point[] pointArr2 = {new Point(iMin, iMin2), new Point(iMax, iMin2), new Point(iMax, i8), new Point(iMin, i8)};
                for (int i11 = 0; i11 < 4; i11++) {
                    int i12 = (int) ((((double) pointArr2[i11].x) * dCos2) - (((double) pointArr2[i11].y) * dSin2));
                    int i13 = (int) ((((double) pointArr2[i11].x) * dSin2) + (((double) pointArr2[i11].y) * dCos2));
                    pointArr2[i11].x = i12;
                    pointArr2[i11].y = i13;
                    pointArr2[i11].offset(i9, i10);
                }
                textBlock = this;
                textBlock.cornerPoints = pointArr2;
            }
        } else {
            textBlock = textBlock2;
        }
        return textBlock.cornerPoints;
    }

    public String getLanguage() {
        String str = this.zzdd;
        if (str != null) {
            return str;
        }
        HashMap map = new HashMap();
        for (zzx zzxVar : this.zzdb) {
            map.put(zzxVar.zzdd, Integer.valueOf((map.containsKey(zzxVar.zzdd) ? ((Integer) map.get(zzxVar.zzdd)).intValue() : 0) + 1));
        }
        String str2 = (String) ((Map.Entry) Collections.max(map.entrySet(), new zza(this))).getKey();
        this.zzdd = str2;
        if (str2 == null || str2.isEmpty()) {
            this.zzdd = C.LANGUAGE_UNDETERMINED;
        }
        return this.zzdd;
    }

    @Override // com.google.android.gms.vision.text.Text
    public String getValue() {
        zzx[] zzxVarArr = this.zzdb;
        if (zzxVarArr.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder(zzxVarArr[0].zzdm);
        for (int i = 1; i < this.zzdb.length; i++) {
            sb.append(ShellAdbUtils.COMMAND_LINE_END);
            sb.append(this.zzdb[i].zzdm);
        }
        return sb.toString();
    }
}
