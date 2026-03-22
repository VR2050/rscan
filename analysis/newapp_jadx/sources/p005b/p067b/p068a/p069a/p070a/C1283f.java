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

/* renamed from: b.b.a.a.a.f */
/* loaded from: classes.dex */
public final class C1283f extends Lambda implements Function1<View, Unit> {

    /* renamed from: c */
    public final /* synthetic */ BaseViewHolder f1000c;

    /* renamed from: e */
    public final /* synthetic */ BaseProviderMultiAdapter<T> f1001e;

    /* renamed from: f */
    public final /* synthetic */ AbstractC1278a<T> f1002f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1283f(BaseViewHolder baseViewHolder, BaseProviderMultiAdapter<T> baseProviderMultiAdapter, AbstractC1278a<T> abstractC1278a) {
        super(1);
        this.f1000c = baseViewHolder;
        this.f1001e = baseProviderMultiAdapter;
        this.f1002f = abstractC1278a;
    }

    @Override // kotlin.jvm.functions.Function1
    public Unit invoke(View view) {
        View view2 = view;
        Intrinsics.checkNotNullParameter(view2, "v");
        int adapterPosition = this.f1000c.getAdapterPosition();
        if (adapterPosition != -1) {
            int headerLayoutCount = adapterPosition - this.f1001e.getHeaderLayoutCount();
            Object obj = this.f1002f;
            BaseViewHolder helper = this.f1000c;
            this.f1001e.getData().get(headerLayoutCount);
            Objects.requireNonNull(obj);
            Intrinsics.checkNotNullParameter(helper, "helper");
            Intrinsics.checkNotNullParameter(view2, "view");
        }
        return Unit.INSTANCE;
    }
}
