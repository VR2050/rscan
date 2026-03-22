package p005b.p067b.p068a.p069a.p070a;

import android.view.View;
import com.chad.library.adapter.base.BaseProviderMultiAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import java.util.Objects;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import p005b.p067b.p068a.p069a.p070a.p071a.AbstractC1278a;

/* renamed from: b.b.a.a.a.g */
/* loaded from: classes.dex */
public final class C1284g extends Lambda implements Function1<View, Unit> {

    /* renamed from: c */
    public final /* synthetic */ BaseViewHolder f1003c;

    /* renamed from: e */
    public final /* synthetic */ BaseProviderMultiAdapter<T> f1004e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1284g(BaseViewHolder baseViewHolder, BaseProviderMultiAdapter<T> baseProviderMultiAdapter) {
        super(1);
        this.f1003c = baseViewHolder;
        this.f1004e = baseProviderMultiAdapter;
    }

    @Override // kotlin.jvm.functions.Function1
    public Unit invoke(View view) {
        View view2 = view;
        Intrinsics.checkNotNullParameter(view2, "it");
        int adapterPosition = this.f1003c.getAdapterPosition();
        if (adapterPosition != -1) {
            int headerLayoutCount = adapterPosition - this.f1004e.getHeaderLayoutCount();
            AbstractC1278a abstractC1278a = (AbstractC1278a) this.f1004e.m3905e().get(this.f1003c.getItemViewType());
            BaseViewHolder helper = this.f1003c;
            this.f1004e.getData().get(headerLayoutCount);
            Objects.requireNonNull(abstractC1278a);
            Intrinsics.checkNotNullParameter(helper, "helper");
            Intrinsics.checkNotNullParameter(view2, "view");
        }
        return Unit.INSTANCE;
    }
}
