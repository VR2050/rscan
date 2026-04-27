package com.google.android.gms.vision.text;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Rect;
import android.graphics.YuvImage;
import android.util.SparseArray;
import com.google.android.gms.internal.vision.zzad;
import com.google.android.gms.internal.vision.zzae;
import com.google.android.gms.internal.vision.zzm;
import com.google.android.gms.internal.vision.zzo;
import com.google.android.gms.internal.vision.zzx;
import com.google.android.gms.internal.vision.zzz;
import com.google.android.gms.vision.Detector;
import com.google.android.gms.vision.Frame;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;

/* JADX INFO: loaded from: classes.dex */
public final class TextRecognizer extends Detector<TextBlock> {
    private final zzad zzdf;

    public static class Builder {
        private zzae zzdg = new zzae();
        private Context zze;

        public Builder(Context context) {
            this.zze = context;
        }

        public TextRecognizer build() {
            return new TextRecognizer(new zzad(this.zze, this.zzdg));
        }
    }

    private TextRecognizer() {
        throw new IllegalStateException("Default constructor called");
    }

    private TextRecognizer(zzad zzadVar) {
        this.zzdf = zzadVar;
    }

    @Override // com.google.android.gms.vision.Detector
    public final SparseArray<TextBlock> detect(Frame frame) {
        byte[] bArrArray;
        Bitmap bitmapDecodeByteArray;
        zzz zzzVar = new zzz(new Rect());
        if (frame == null) {
            throw new IllegalArgumentException("No frame supplied.");
        }
        zzm zzmVarZzc = zzm.zzc(frame);
        if (frame.getBitmap() != null) {
            bitmapDecodeByteArray = frame.getBitmap();
        } else {
            Frame.Metadata metadata = frame.getMetadata();
            ByteBuffer grayscaleImageData = frame.getGrayscaleImageData();
            int format = metadata.getFormat();
            int i = zzmVarZzc.width;
            int i2 = zzmVarZzc.height;
            if (grayscaleImageData.hasArray() && grayscaleImageData.arrayOffset() == 0) {
                bArrArray = grayscaleImageData.array();
            } else {
                byte[] bArr = new byte[grayscaleImageData.capacity()];
                grayscaleImageData.get(bArr);
                bArrArray = bArr;
            }
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            new YuvImage(bArrArray, format, i, i2, null).compressToJpeg(new Rect(0, 0, i, i2), 100, byteArrayOutputStream);
            byte[] byteArray = byteArrayOutputStream.toByteArray();
            bitmapDecodeByteArray = BitmapFactory.decodeByteArray(byteArray, 0, byteArray.length);
        }
        Bitmap bitmapZzb = zzo.zzb(bitmapDecodeByteArray, zzmVarZzc);
        if (!zzzVar.zzdr.isEmpty()) {
            Rect rect = zzzVar.zzdr;
            int width = frame.getMetadata().getWidth();
            int height = frame.getMetadata().getHeight();
            int i3 = zzmVarZzc.rotation;
            if (i3 == 1) {
                rect = new Rect(height - rect.bottom, rect.left, height - rect.top, rect.right);
            } else if (i3 == 2) {
                rect = new Rect(width - rect.right, height - rect.bottom, width - rect.left, height - rect.top);
            } else if (i3 == 3) {
                rect = new Rect(rect.top, width - rect.right, rect.bottom, width - rect.left);
            }
            zzzVar.zzdr.set(rect);
        }
        zzmVarZzc.rotation = 0;
        zzx[] zzxVarArrZza = this.zzdf.zza(bitmapZzb, zzmVarZzc, zzzVar);
        SparseArray sparseArray = new SparseArray();
        for (zzx zzxVar : zzxVarArrZza) {
            SparseArray sparseArray2 = (SparseArray) sparseArray.get(zzxVar.zzdp);
            if (sparseArray2 == null) {
                sparseArray2 = new SparseArray();
                sparseArray.append(zzxVar.zzdp, sparseArray2);
            }
            sparseArray2.append(zzxVar.zzdq, zzxVar);
        }
        SparseArray<TextBlock> sparseArray3 = new SparseArray<>(sparseArray.size());
        for (int i4 = 0; i4 < sparseArray.size(); i4++) {
            sparseArray3.append(sparseArray.keyAt(i4), new TextBlock((SparseArray) sparseArray.valueAt(i4)));
        }
        return sparseArray3;
    }

    @Override // com.google.android.gms.vision.Detector
    public final boolean isOperational() {
        return this.zzdf.isOperational();
    }

    @Override // com.google.android.gms.vision.Detector
    public final void release() {
        super.release();
        this.zzdf.zzo();
    }
}
