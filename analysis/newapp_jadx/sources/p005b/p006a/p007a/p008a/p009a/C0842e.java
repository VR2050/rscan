package p005b.p006a.p007a.p008a.p009a;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.LinearSmoothScroller;
import androidx.recyclerview.widget.RecyclerView;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import tv.danmaku.ijk.media.player.IjkMediaCodecInfo;

/* renamed from: b.a.a.a.a.e */
/* loaded from: classes2.dex */
public final class C0842e {

    /* renamed from: a */
    @NotNull
    public final RecyclerView f237a;

    /* renamed from: b */
    public final long f238b;

    /* renamed from: c */
    @NotNull
    public final Handler f239c;

    /* renamed from: d */
    public int f240d;

    /* renamed from: e */
    public boolean f241e;

    /* renamed from: f */
    public final int f242f;

    /* renamed from: g */
    @NotNull
    public final a f243g;

    /* renamed from: b.a.a.a.a.e$a */
    public static final class a implements Runnable {
        public a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            RecyclerView.Adapter adapter = C0842e.this.f237a.getAdapter();
            if (adapter == null || adapter.getItemCount() == 0) {
                return;
            }
            if (!C0842e.this.f241e) {
                int itemCount = adapter.getItemCount();
                C0842e c0842e = C0842e.this;
                int i2 = itemCount - c0842e.f242f;
                int i3 = c0842e.f240d;
                if (i3 >= i2) {
                    c0842e.f240d = 0;
                } else {
                    c0842e.f240d = i3 + 1;
                }
                int i4 = c0842e.f240d;
                RecyclerView.LayoutManager layoutManager = c0842e.f237a.getLayoutManager();
                LinearLayoutManager linearLayoutManager = layoutManager instanceof LinearLayoutManager ? (LinearLayoutManager) layoutManager : null;
                if (linearLayoutManager != null) {
                    final Context context = c0842e.f237a.getContext();
                    LinearSmoothScroller linearSmoothScroller = new LinearSmoothScroller(context) { // from class: com.jbzd.media.movecartoons.utils.AutoScrollHelper$smoothScrollToPositionExactly$smoothScroller$1
                        @Override // androidx.recyclerview.widget.LinearSmoothScroller
                        public int calculateTimeForScrolling(int dx) {
                            return IjkMediaCodecInfo.RANK_SECURE;
                        }

                        @Override // androidx.recyclerview.widget.LinearSmoothScroller
                        public int getHorizontalSnapPreference() {
                            return -1;
                        }
                    };
                    linearSmoothScroller.setTargetPosition(i4);
                    linearLayoutManager.startSmoothScroll(linearSmoothScroller);
                }
            }
            C0842e c0842e2 = C0842e.this;
            c0842e2.f239c.postDelayed(this, c0842e2.f238b);
        }
    }

    public C0842e(@NotNull RecyclerView recyclerView, long j2) {
        Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
        this.f237a = recyclerView;
        this.f238b = j2;
        this.f239c = new Handler(Looper.getMainLooper());
        this.f242f = 3;
        this.f243g = new a();
    }

    /* renamed from: a */
    public final void m180a() {
        this.f239c.removeCallbacks(this.f243g);
        this.f239c.postDelayed(this.f243g, this.f238b);
    }

    /* renamed from: b */
    public final void m181b() {
        this.f239c.removeCallbacks(this.f243g);
    }
}
