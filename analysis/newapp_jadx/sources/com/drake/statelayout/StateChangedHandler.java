package com.drake.statelayout;

import android.view.View;
import androidx.core.app.NotificationCompat;
import com.drake.statelayout.StateLayout;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\bf\u0018\u0000 \f2\u00020\u0001:\u0001\fJ*\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\t2\b\u0010\n\u001a\u0004\u0018\u00010\u0001H\u0016J*\u0010\u000b\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\t2\b\u0010\n\u001a\u0004\u0018\u00010\u0001H\u0016¨\u0006\r"}, m5311d2 = {"Lcom/drake/statelayout/StateChangedHandler;", "", "onAdd", "", "container", "Lcom/drake/statelayout/StateLayout;", "state", "Landroid/view/View;", NotificationCompat.CATEGORY_STATUS, "Lcom/drake/statelayout/Status;", "tag", "onRemove", "DEFAULT", "statelayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.i.b.b, reason: from Kotlin metadata */
/* loaded from: classes.dex */
public interface StateChangedHandler {

    @Metadata(m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002¨\u0006\u0003"}, m5311d2 = {"Lcom/drake/statelayout/StateChangedHandler$DEFAULT;", "Lcom/drake/statelayout/StateChangedHandler;", "()V", "statelayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: b.i.b.b$a */
    public static final class a implements StateChangedHandler {

        /* renamed from: a */
        public static final /* synthetic */ a f2874a = new a();

        @Override // com.drake.statelayout.StateChangedHandler
        /* renamed from: a */
        public void mo1209a(@NotNull StateLayout container, @NotNull View state, @NotNull Status status, @Nullable Object obj) {
            Intrinsics.checkNotNullParameter(container, "container");
            Intrinsics.checkNotNullParameter(state, "state");
            Intrinsics.checkNotNullParameter(status, "status");
            state.setVisibility(8);
        }

        @Override // com.drake.statelayout.StateChangedHandler
        /* renamed from: b */
        public void mo1210b(@NotNull StateLayout container, @NotNull View state, @NotNull Status status, @Nullable Object obj) {
            Intrinsics.checkNotNullParameter(container, "container");
            Intrinsics.checkNotNullParameter(state, "state");
            Intrinsics.checkNotNullParameter(status, "status");
            if (container.indexOfChild(state) != -1) {
                state.setVisibility(0);
            } else {
                container.addView(state);
            }
        }
    }

    /* renamed from: a */
    void mo1209a(@NotNull StateLayout stateLayout, @NotNull View view, @NotNull Status status, @Nullable Object obj);

    /* renamed from: b */
    void mo1210b(@NotNull StateLayout stateLayout, @NotNull View view, @NotNull Status status, @Nullable Object obj);
}
