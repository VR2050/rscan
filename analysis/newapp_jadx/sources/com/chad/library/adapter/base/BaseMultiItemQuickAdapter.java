package com.chad.library.adapter.base;

import android.util.SparseIntArray;
import android.view.ViewGroup;
import androidx.annotation.LayoutRes;
import androidx.exifinterface.media.ExifInterface;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.LazyThreadSafetyMode;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1296a;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000<\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010!\n\u0002\b\u0004\b&\u0018\u0000*\b\b\u0000\u0010\u0002*\u00020\u0001*\b\b\u0001\u0010\u0004*\u00020\u00032\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u0005B\u0019\u0012\u0010\b\u0002\u0010\u001b\u001a\n\u0012\u0004\u0012\u00028\u0000\u0018\u00010\u001a¢\u0006\u0004\b\u001c\u0010\u001dJ\u0017\u0010\b\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\u0006H\u0014¢\u0006\u0004\b\b\u0010\tJ\u001f\u0010\r\u001a\u00028\u00012\u0006\u0010\u000b\u001a\u00020\n2\u0006\u0010\f\u001a\u00020\u0006H\u0014¢\u0006\u0004\b\r\u0010\u000eJ!\u0010\u0012\u001a\u00020\u00112\u0006\u0010\u000f\u001a\u00020\u00062\b\b\u0001\u0010\u0010\u001a\u00020\u0006H\u0004¢\u0006\u0004\b\u0012\u0010\u0013R\u001d\u0010\u0019\u001a\u00020\u00148B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0015\u0010\u0016\u001a\u0004\b\u0017\u0010\u0018¨\u0006\u001e"}, m5311d2 = {"Lcom/chad/library/adapter/base/BaseMultiItemQuickAdapter;", "Lb/b/a/a/a/j/a;", ExifInterface.GPS_DIRECTION_TRUE, "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "VH", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "", "position", "getDefItemViewType", "(I)I", "Landroid/view/ViewGroup;", "parent", "viewType", "onCreateDefViewHolder", "(Landroid/view/ViewGroup;I)Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "type", "layoutResId", "", "addItemType", "(II)V", "Landroid/util/SparseIntArray;", "layouts$delegate", "Lkotlin/Lazy;", "getLayouts", "()Landroid/util/SparseIntArray;", "layouts", "", "data", "<init>", "(Ljava/util/List;)V", "com.github.CymChad.brvah"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes.dex */
public abstract class BaseMultiItemQuickAdapter<T extends InterfaceC1296a, VH extends BaseViewHolder> extends BaseQuickAdapter<T, VH> {

    /* renamed from: layouts$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy layouts;

    /* renamed from: com.chad.library.adapter.base.BaseMultiItemQuickAdapter$a */
    public static final class C3225a extends Lambda implements Function0<SparseIntArray> {

        /* renamed from: c */
        public static final C3225a f8867c = new C3225a();

        public C3225a() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public SparseIntArray invoke() {
            return new SparseIntArray();
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public BaseMultiItemQuickAdapter() {
        this(null, 1, 0 == true ? 1 : 0);
    }

    public /* synthetic */ BaseMultiItemQuickAdapter(List list, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this((i2 & 1) != 0 ? null : list);
    }

    private final SparseIntArray getLayouts() {
        return (SparseIntArray) this.layouts.getValue();
    }

    public final void addItemType(int type, @LayoutRes int layoutResId) {
        getLayouts().put(type, layoutResId);
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public int getDefItemViewType(int position) {
        return ((InterfaceC1296a) getData().get(position)).getItemType();
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    @NotNull
    public VH onCreateDefViewHolder(@NotNull ViewGroup parent, int viewType) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        int i2 = getLayouts().get(viewType);
        if (i2 != 0) {
            return createBaseViewHolder(parent, i2);
        }
        throw new IllegalArgumentException(C1499a.m628n("ViewType: ", viewType, " found layoutResId，please use addItemType() first!").toString());
    }

    public BaseMultiItemQuickAdapter(@Nullable List<T> list) {
        super(0, list);
        this.layouts = LazyKt__LazyJVMKt.lazy(LazyThreadSafetyMode.NONE, (Function0) C3225a.f8867c);
    }
}
