package com.google.android.gms.internal.vision;

import android.content.Context;
import android.graphics.Bitmap;
import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.dynamic.ObjectWrapper;
import com.google.android.gms.dynamite.DynamiteModule;

/* JADX INFO: loaded from: classes.dex */
public final class zzad extends zzl<zzt> {
    private final zzae zzdg;

    public zzad(Context context, zzae zzaeVar) {
        super(context, "TextNativeHandle", "text");
        this.zzdg = zzaeVar;
        zzp();
    }

    @Override // com.google.android.gms.internal.vision.zzl
    protected final /* synthetic */ zzt zza(DynamiteModule dynamiteModule, Context context) throws RemoteException, DynamiteModule.LoadingException {
        zzv zzwVar;
        IBinder iBinderInstantiate = dynamiteModule.instantiate("com.google.android.gms.vision.text.ChimeraNativeTextRecognizerCreator");
        if (iBinderInstantiate == null) {
            zzwVar = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = iBinderInstantiate.queryLocalInterface("com.google.android.gms.vision.text.internal.client.INativeTextRecognizerCreator");
            zzwVar = iInterfaceQueryLocalInterface instanceof zzv ? (zzv) iInterfaceQueryLocalInterface : new zzw(iBinderInstantiate);
        }
        if (zzwVar == null) {
            return null;
        }
        return zzwVar.zza(ObjectWrapper.wrap(context), this.zzdg);
    }

    public final zzx[] zza(Bitmap bitmap, zzm zzmVar, zzz zzzVar) {
        if (!isOperational()) {
            return new zzx[0];
        }
        try {
            return zzp().zza(ObjectWrapper.wrap(bitmap), zzmVar, zzzVar);
        } catch (RemoteException e) {
            Log.e("TextNativeHandle", "Error calling native text recognizer", e);
            return new zzx[0];
        }
    }

    @Override // com.google.android.gms.internal.vision.zzl
    protected final void zzm() throws RemoteException {
        zzp().zzq();
    }
}
