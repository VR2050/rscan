package com.chad.library.adapter.base;

import android.content.Context;
import android.util.SparseArray;
import android.view.View;
import android.view.ViewGroup;
import androidx.exifinterface.media.ExifInterface;
import com.chad.library.adapter.base.BaseProviderMultiAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.LazyThreadSafetyMode;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p067b.p068a.p069a.p070a.C1283f;
import p005b.p067b.p068a.p069a.p070a.C1284g;
import p005b.p067b.p068a.p069a.p070a.p071a.AbstractC1278a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p146l.C1568e;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000L\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0000\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u0000\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010!\n\u0002\b\u0003\b&\u0018\u0000*\u0004\b\u0000\u0010\u00012\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00020\u00030\u0002B\u0019\u0012\u0010\b\u0002\u0010\u0005\u001a\n\u0012\u0004\u0012\u00028\u0000\u0018\u00010%¢\u0006\u0004\b&\u0010'J%\u0010\b\u001a\u00020\u00062\f\u0010\u0005\u001a\b\u0012\u0004\u0012\u00028\u00000\u00042\u0006\u0010\u0007\u001a\u00020\u0006H$¢\u0006\u0004\b\b\u0010\tJ\u001f\u0010\r\u001a\u00020\u00032\u0006\u0010\u000b\u001a\u00020\n2\u0006\u0010\f\u001a\u00020\u0006H\u0014¢\u0006\u0004\b\r\u0010\u000eJ\u0017\u0010\u000f\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\u0006H\u0014¢\u0006\u0004\b\u000f\u0010\u0010J\u001f\u0010\u0014\u001a\u00020\u00132\u0006\u0010\u0011\u001a\u00020\u00032\u0006\u0010\u0012\u001a\u00028\u0000H\u0014¢\u0006\u0004\b\u0014\u0010\u0015J-\u0010\u0014\u001a\u00020\u00132\u0006\u0010\u0011\u001a\u00020\u00032\u0006\u0010\u0012\u001a\u00028\u00002\f\u0010\u0017\u001a\b\u0012\u0004\u0012\u00020\u00160\u0004H\u0014¢\u0006\u0004\b\u0014\u0010\u0018J\u001f\u0010\u001a\u001a\u00020\u00132\u0006\u0010\u0019\u001a\u00020\u00032\u0006\u0010\f\u001a\u00020\u0006H\u0014¢\u0006\u0004\b\u001a\u0010\u001bJ\u001f\u0010\u001d\u001a\n\u0012\u0004\u0012\u00028\u0000\u0018\u00010\u001c2\u0006\u0010\f\u001a\u00020\u0006H\u0014¢\u0006\u0004\b\u001d\u0010\u001eR)\u0010$\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00028\u00000\u001c0\u001f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b \u0010!\u001a\u0004\b\"\u0010#¨\u0006("}, m5311d2 = {"Lcom/chad/library/adapter/base/BaseProviderMultiAdapter;", ExifInterface.GPS_DIRECTION_TRUE, "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "", "data", "", "position", "d", "(Ljava/util/List;I)I", "Landroid/view/ViewGroup;", "parent", "viewType", "onCreateDefViewHolder", "(Landroid/view/ViewGroup;I)Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "getDefItemViewType", "(I)I", "helper", "item", "", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Ljava/lang/Object;)V", "", "payloads", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Ljava/lang/Object;Ljava/util/List;)V", "viewHolder", "bindViewClickListener", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;I)V", "Lb/b/a/a/a/a/a;", "c", "(I)Lb/b/a/a/a/a/a;", "Landroid/util/SparseArray;", "a", "Lkotlin/Lazy;", C1568e.f1949a, "()Landroid/util/SparseArray;", "mItemProviders", "", "<init>", "(Ljava/util/List;)V", "com.github.CymChad.brvah"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes.dex */
public abstract class BaseProviderMultiAdapter<T> extends BaseQuickAdapter<T, BaseViewHolder> {

    /* renamed from: a, reason: from kotlin metadata */
    @NotNull
    public final Lazy mItemProviders;

    /* renamed from: com.chad.library.adapter.base.BaseProviderMultiAdapter$a */
    public static final class C3226a extends Lambda implements Function0<SparseArray<AbstractC1278a<T>>> {

        /* renamed from: c */
        public static final C3226a f8870c = new C3226a();

        public C3226a() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public Object invoke() {
            return new SparseArray();
        }
    }

    public BaseProviderMultiAdapter() {
        super(0, null);
        this.mItemProviders = LazyKt__LazyJVMKt.lazy(LazyThreadSafetyMode.NONE, (Function0) C3226a.f8870c);
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void bindViewClickListener(@NotNull final BaseViewHolder viewHolder, int viewType) {
        final AbstractC1278a<T> abstractC1278a;
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        super.bindViewClickListener(viewHolder, viewType);
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        if (getMOnItemClickListener() == null) {
            C4195m.m4779M(viewHolder.itemView, 0L, new C1284g(viewHolder, this), 1);
        }
        if (getMOnItemLongClickListener() == null) {
            viewHolder.itemView.setOnLongClickListener(new View.OnLongClickListener() { // from class: b.b.a.a.a.b
                @Override // android.view.View.OnLongClickListener
                public final boolean onLongClick(View view) {
                    BaseViewHolder helper = BaseViewHolder.this;
                    BaseProviderMultiAdapter this$0 = this;
                    Intrinsics.checkNotNullParameter(helper, "$viewHolder");
                    Intrinsics.checkNotNullParameter(this$0, "this$0");
                    int adapterPosition = helper.getAdapterPosition();
                    if (adapterPosition == -1) {
                        return false;
                    }
                    int headerLayoutCount = adapterPosition - this$0.getHeaderLayoutCount();
                    AbstractC1278a abstractC1278a2 = (AbstractC1278a) this$0.m3905e().get(helper.getItemViewType());
                    Intrinsics.checkNotNullExpressionValue(view, "it");
                    this$0.getData().get(headerLayoutCount);
                    Objects.requireNonNull(abstractC1278a2);
                    Intrinsics.checkNotNullParameter(helper, "helper");
                    Intrinsics.checkNotNullParameter(view, "view");
                    return false;
                }
            });
        }
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        if (getMOnItemChildClickListener() == null) {
            AbstractC1278a<T> abstractC1278a2 = m3905e().get(viewType);
            if (abstractC1278a2 == null) {
                return;
            }
            Iterator<T> it = ((ArrayList) abstractC1278a2.f986a.getValue()).iterator();
            while (it.hasNext()) {
                View findViewById = viewHolder.itemView.findViewById(((Number) it.next()).intValue());
                if (findViewById != null) {
                    if (!findViewById.isClickable()) {
                        findViewById.setClickable(true);
                    }
                    C4195m.m4779M(findViewById, 0L, new C1283f(viewHolder, this, abstractC1278a2), 1);
                }
            }
        }
        if (getMOnItemChildLongClickListener() != null || (abstractC1278a = m3905e().get(viewType)) == null) {
            return;
        }
        Iterator<T> it2 = ((ArrayList) abstractC1278a.f987b.getValue()).iterator();
        while (it2.hasNext()) {
            View findViewById2 = viewHolder.itemView.findViewById(((Number) it2.next()).intValue());
            if (findViewById2 != null) {
                if (!findViewById2.isLongClickable()) {
                    findViewById2.setLongClickable(true);
                }
                findViewById2.setOnLongClickListener(new View.OnLongClickListener() { // from class: b.b.a.a.a.c
                    @Override // android.view.View.OnLongClickListener
                    public final boolean onLongClick(View view) {
                        BaseViewHolder helper = BaseViewHolder.this;
                        BaseProviderMultiAdapter this$0 = this;
                        AbstractC1278a provider = abstractC1278a;
                        Intrinsics.checkNotNullParameter(helper, "$viewHolder");
                        Intrinsics.checkNotNullParameter(this$0, "this$0");
                        Intrinsics.checkNotNullParameter(provider, "$provider");
                        int adapterPosition = helper.getAdapterPosition();
                        if (adapterPosition == -1) {
                            return false;
                        }
                        int headerLayoutCount = adapterPosition - this$0.getHeaderLayoutCount();
                        Intrinsics.checkNotNullExpressionValue(view, "v");
                        this$0.getData().get(headerLayoutCount);
                        Objects.requireNonNull(provider);
                        Intrinsics.checkNotNullParameter(helper, "helper");
                        Intrinsics.checkNotNullParameter(view, "view");
                        return false;
                    }
                });
            }
        }
    }

    @Nullable
    /* renamed from: c */
    public AbstractC1278a<T> m3903c(int viewType) {
        return m3905e().get(viewType);
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void convert(@NotNull BaseViewHolder helper, T item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        AbstractC1278a<T> m3903c = m3903c(helper.getItemViewType());
        Intrinsics.checkNotNull(m3903c);
        m3903c.m305a(helper, item);
    }

    /* renamed from: d */
    public abstract int m3904d(@NotNull List<? extends T> data, int position);

    /* renamed from: e */
    public final SparseArray<AbstractC1278a<T>> m3905e() {
        return (SparseArray) this.mItemProviders.getValue();
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public int getDefItemViewType(int position) {
        return m3904d(getData(), position);
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    @NotNull
    public BaseViewHolder onCreateDefViewHolder(@NotNull ViewGroup parent, int viewType) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        AbstractC1278a<T> abstractC1278a = m3905e().get(viewType);
        if (abstractC1278a == null) {
            throw new IllegalStateException(C1499a.m628n("ViewType: ", viewType, " no such provider found，please use addItemProvider() first!").toString());
        }
        Context context = parent.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "parent.context");
        Intrinsics.checkNotNullParameter(context, "<set-?>");
        Intrinsics.checkNotNullParameter(parent, "parent");
        BaseViewHolder viewHolder = new BaseViewHolder(C4195m.m4803e0(parent, abstractC1278a.m306b()));
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        return viewHolder;
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void convert(@NotNull BaseViewHolder helper, T item, @NotNull List<? extends Object> payloads) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(payloads, "payloads");
        AbstractC1278a<T> m3903c = m3903c(helper.getItemViewType());
        Intrinsics.checkNotNull(m3903c);
        Objects.requireNonNull(m3903c);
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(payloads, "payloads");
    }

    public BaseProviderMultiAdapter(@Nullable List<T> list) {
        super(0, null);
        this.mItemProviders = LazyKt__LazyJVMKt.lazy(LazyThreadSafetyMode.NONE, (Function0) C3226a.f8870c);
    }
}
