package p005b.p006a.p007a.p008a.p023s;

import android.content.ComponentName;
import android.content.ServiceConnection;
import android.os.IBinder;
import com.jbzd.media.movecartoons.service.AudioPlayerService;
import java.util.Objects;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: b.a.a.a.s.d0 */
/* loaded from: classes2.dex */
public final class C0959d0 {

    /* renamed from: a */
    @Nullable
    public static C0959d0 f570a;

    /* renamed from: b */
    public AudioPlayerService f571b;

    /* renamed from: c */
    public boolean f572c;

    /* renamed from: d */
    @NotNull
    public final ServiceConnection f573d = new a();

    /* renamed from: b.a.a.a.s.d0$a */
    public static final class a implements ServiceConnection {
        public a() {
        }

        @Override // android.content.ServiceConnection
        public void onServiceConnected(@Nullable ComponentName componentName, @Nullable IBinder iBinder) {
            AudioPlayerService.BinderC3637c binderC3637c = iBinder instanceof AudioPlayerService.BinderC3637c ? (AudioPlayerService.BinderC3637c) iBinder : null;
            C0959d0 c0959d0 = C0959d0.this;
            AudioPlayerService audioPlayerService = binderC3637c != null ? binderC3637c.f10096a : null;
            if (audioPlayerService == null) {
                return;
            }
            Objects.requireNonNull(c0959d0);
            Intrinsics.checkNotNullParameter(audioPlayerService, "<set-?>");
            c0959d0.f571b = audioPlayerService;
            C0959d0.this.m299b(true);
        }

        @Override // android.content.ServiceConnection
        public void onServiceDisconnected(@Nullable ComponentName componentName) {
            C0959d0.this.m299b(false);
        }
    }

    public C0959d0() {
    }

    @NotNull
    /* renamed from: a */
    public final AudioPlayerService m298a() {
        AudioPlayerService audioPlayerService = this.f571b;
        if (audioPlayerService != null) {
            return audioPlayerService;
        }
        Intrinsics.throwUninitializedPropertyAccessException("audioPlayerService");
        throw null;
    }

    /* renamed from: b */
    public final void m299b(boolean z) {
        m298a().isServiceBound = z;
    }

    public C0959d0(DefaultConstructorMarker defaultConstructorMarker) {
    }
}
