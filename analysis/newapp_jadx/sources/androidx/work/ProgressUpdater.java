package androidx.work;

import android.content.Context;
import androidx.annotation.NonNull;
import java.util.UUID;
import p005b.p199l.p255b.p256a.p257a.InterfaceFutureC2413a;

/* loaded from: classes.dex */
public interface ProgressUpdater {
    @NonNull
    InterfaceFutureC2413a<Void> updateProgress(@NonNull Context context, @NonNull UUID uuid, @NonNull Data data);
}
