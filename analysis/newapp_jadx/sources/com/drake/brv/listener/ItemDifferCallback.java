package com.drake.brv.listener;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5310d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0006\bf\u0018\u0000 \b2\u00020\u0001:\u0001\bJ\u0018\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00012\u0006\u0010\u0005\u001a\u00020\u0001H\u0016J\u0018\u0010\u0006\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00012\u0006\u0010\u0005\u001a\u00020\u0001H\u0016J\u001a\u0010\u0007\u001a\u0004\u0018\u00010\u00012\u0006\u0010\u0004\u001a\u00020\u00012\u0006\u0010\u0005\u001a\u00020\u0001H\u0016¨\u0006\t"}, m5311d2 = {"Lcom/drake/brv/listener/ItemDifferCallback;", "", "areContentsTheSame", "", "oldItem", "newItem", "areItemsTheSame", "getChangePayload", "DEFAULT", "brv_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.i.a.k.a, reason: from Kotlin metadata */
/* loaded from: classes.dex */
public interface ItemDifferCallback {

    /* renamed from: a */
    public static final /* synthetic */ int f2865a = 0;

    @Metadata(m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002¨\u0006\u0003"}, m5311d2 = {"Lcom/drake/brv/listener/ItemDifferCallback$DEFAULT;", "Lcom/drake/brv/listener/ItemDifferCallback;", "()V", "brv_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: b.i.a.k.a$a */
    public static final class a implements ItemDifferCallback {

        /* renamed from: b */
        public static final /* synthetic */ a f2866b = new a();

        @Override // com.drake.brv.listener.ItemDifferCallback
        @Nullable
        /* renamed from: a */
        public Object mo1203a(@NotNull Object oldItem, @NotNull Object newItem) {
            Intrinsics.checkNotNullParameter(this, "this");
            Intrinsics.checkNotNullParameter(oldItem, "oldItem");
            Intrinsics.checkNotNullParameter(newItem, "newItem");
            return null;
        }

        @Override // com.drake.brv.listener.ItemDifferCallback
        /* renamed from: b */
        public boolean mo1204b(@NotNull Object oldItem, @NotNull Object newItem) {
            Intrinsics.checkNotNullParameter(this, "this");
            Intrinsics.checkNotNullParameter(oldItem, "oldItem");
            Intrinsics.checkNotNullParameter(newItem, "newItem");
            return Intrinsics.areEqual(oldItem, newItem);
        }

        @Override // com.drake.brv.listener.ItemDifferCallback
        /* renamed from: c */
        public boolean mo1205c(@NotNull Object oldItem, @NotNull Object newItem) {
            Intrinsics.checkNotNullParameter(this, "this");
            Intrinsics.checkNotNullParameter(oldItem, "oldItem");
            Intrinsics.checkNotNullParameter(newItem, "newItem");
            return Intrinsics.areEqual(oldItem, newItem);
        }
    }

    @Nullable
    /* renamed from: a */
    Object mo1203a(@NotNull Object obj, @NotNull Object obj2);

    /* renamed from: b */
    boolean mo1204b(@NotNull Object obj, @NotNull Object obj2);

    /* renamed from: c */
    boolean mo1205c(@NotNull Object obj, @NotNull Object obj2);
}
