package androidx.core.app;

import android.app.PendingIntent;
import androidx.core.graphics.drawable.IconCompat;

/* JADX INFO: loaded from: classes.dex */
public class RemoteActionCompatParcelizer {
    public static RemoteActionCompat read(androidx.versionedparcelable.a aVar) {
        RemoteActionCompat remoteActionCompat = new RemoteActionCompat();
        remoteActionCompat.f4218a = (IconCompat) aVar.v(remoteActionCompat.f4218a, 1);
        remoteActionCompat.f4219b = aVar.l(remoteActionCompat.f4219b, 2);
        remoteActionCompat.f4220c = aVar.l(remoteActionCompat.f4220c, 3);
        remoteActionCompat.f4221d = (PendingIntent) aVar.r(remoteActionCompat.f4221d, 4);
        remoteActionCompat.f4222e = aVar.h(remoteActionCompat.f4222e, 5);
        remoteActionCompat.f4223f = aVar.h(remoteActionCompat.f4223f, 6);
        return remoteActionCompat;
    }

    public static void write(RemoteActionCompat remoteActionCompat, androidx.versionedparcelable.a aVar) {
        aVar.x(false, false);
        aVar.M(remoteActionCompat.f4218a, 1);
        aVar.D(remoteActionCompat.f4219b, 2);
        aVar.D(remoteActionCompat.f4220c, 3);
        aVar.H(remoteActionCompat.f4221d, 4);
        aVar.z(remoteActionCompat.f4222e, 5);
        aVar.z(remoteActionCompat.f4223f, 6);
    }
}
