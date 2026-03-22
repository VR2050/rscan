package com.jbzd.media.movecartoons.p396ui.search.child;

import android.os.Bundle;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentViewModelLazyKt;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelStore;
import androidx.lifecycle.ViewModelStoreOwner;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.bean.response.tag.TagInfoBean;
import com.jbzd.media.movecartoons.core.MyThemeViewModelFragment;
import com.jbzd.media.movecartoons.p396ui.search.child.TagInfoFragment;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p143g.p144a.C1558h;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p336c.C2851b;
import p005b.p327w.p330b.p336c.C2852c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0002\b\u000e\u0018\u0000 \u00182\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001\u0018B\u0007¢\u0006\u0004\b\u0017\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\t\u0010\nR\u001f\u0010\u0010\u001a\u0004\u0018\u00010\u000b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\f\u0010\r\u001a\u0004\b\u000e\u0010\u000fR\u001d\u0010\u0013\u001a\u00020\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0011\u0010\r\u001a\u0004\b\u0012\u0010\nR\u001f\u0010\u0016\u001a\u0004\u0018\u00010\u000b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0014\u0010\r\u001a\u0004\b\u0015\u0010\u000f¨\u0006\u0019"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/TagInfoFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeViewModelFragment;", "Lcom/jbzd/media/movecartoons/ui/search/child/InfoModel;", "", "initViews", "()V", "", "getLayout", "()I", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/search/child/InfoModel;", "", "name$delegate", "Lkotlin/Lazy;", "getName", "()Ljava/lang/String;", TagInfoFragment.KEY_NAME, "viewModel$delegate", "getViewModel", "viewModel", "mTagId$delegate", "getMTagId", "mTagId", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class TagInfoFragment extends MyThemeViewModelFragment<InfoModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static final String KEY_ID = "id";

    @NotNull
    private static final String KEY_NAME = "name";

    /* renamed from: mTagId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mTagId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.child.TagInfoFragment$mTagId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return TagInfoFragment.this.requireArguments().getString("id");
        }
    });

    /* renamed from: name$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy name = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.child.TagInfoFragment$name$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return TagInfoFragment.this.requireArguments().getString("name");
        }
    });

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000b\u0010\fJ#\u0010\u0006\u001a\u00020\u00052\b\u0010\u0003\u001a\u0004\u0018\u00010\u00022\n\b\u0002\u0010\u0004\u001a\u0004\u0018\u00010\u0002¢\u0006\u0004\b\u0006\u0010\u0007R\u0016\u0010\b\u001a\u00020\u00028\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\b\u0010\tR\u0016\u0010\n\u001a\u00020\u00028\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\n\u0010\t¨\u0006\r"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/TagInfoFragment$Companion;", "", "", TagInfoFragment.KEY_ID, TagInfoFragment.KEY_NAME, "Lcom/jbzd/media/movecartoons/ui/search/child/TagInfoFragment;", "instance", "(Ljava/lang/String;Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/search/child/TagInfoFragment;", "KEY_ID", "Ljava/lang/String;", "KEY_NAME", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static /* synthetic */ TagInfoFragment instance$default(Companion companion, String str, String str2, int i2, Object obj) {
            if ((i2 & 2) != 0) {
                str2 = null;
            }
            return companion.instance(str, str2);
        }

        @NotNull
        public final TagInfoFragment instance(@Nullable String id, @Nullable String name) {
            TagInfoFragment tagInfoFragment = new TagInfoFragment();
            Bundle bundle = new Bundle();
            bundle.putString(TagInfoFragment.KEY_ID, id);
            bundle.putString(TagInfoFragment.KEY_NAME, name);
            Unit unit = Unit.INSTANCE;
            tagInfoFragment.setArguments(bundle);
            return tagInfoFragment;
        }
    }

    public TagInfoFragment() {
        final Function0<Fragment> function0 = new Function0<Fragment>() { // from class: com.jbzd.media.movecartoons.ui.search.child.TagInfoFragment$special$$inlined$viewModels$default$1
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final Fragment invoke() {
                return Fragment.this;
            }
        };
        this.viewModel = FragmentViewModelLazyKt.createViewModelLazy(this, Reflection.getOrCreateKotlinClass(InfoModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.search.child.TagInfoFragment$special$$inlined$viewModels$default$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ViewModelStore invoke() {
                ViewModelStore viewModelStore = ((ViewModelStoreOwner) Function0.this.invoke()).getViewModelStore();
                Intrinsics.checkExpressionValueIsNotNull(viewModelStore, "ownerProducer().viewModelStore");
                return viewModelStore;
            }
        }, null);
    }

    private final String getMTagId() {
        return (String) this.mTagId.getValue();
    }

    private final String getName() {
        return (String) this.name.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5986initViews$lambda1$lambda0(TagInfoFragment this$0, TagInfoBean tagInfoBean) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        C2852c m2467d2 = C2354n.m2467d2(this$0.requireActivity());
        String str = tagInfoBean.img;
        if (str == null) {
            str = "";
        }
        C1558h mo770c = m2467d2.mo770c();
        mo770c.mo763X(str);
        C2851b m3292f0 = ((C2851b) mo770c).m3292f0();
        View view = this$0.getView();
        m3292f0.m757R((ImageView) (view == null ? null : view.findViewById(R$id.civ_head)));
        View view2 = this$0.getView();
        TextView textView = (TextView) (view2 == null ? null : view2.findViewById(R$id.tv_postdetail_nickname));
        String str2 = tagInfoBean.name;
        if (str2 == null) {
            str2 = "";
        }
        textView.setText(str2);
        View view3 = this$0.getView();
        TextView textView2 = (TextView) (view3 != null ? view3.findViewById(R$id.tv_desc) : null);
        String str3 = tagInfoBean.desc;
        textView2.setText(str3 != null ? str3 : "");
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseThemeViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.frag_tag_detail;
    }

    @NotNull
    public final InfoModel getViewModel() {
        return (InfoModel) this.viewModel.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        InfoModel viewModel = getViewModel();
        InfoModel.load$default(viewModel, getMTagId(), false, 2, null);
        viewModel.getInfoBean().observe(requireActivity(), new Observer() { // from class: b.a.a.a.t.m.j.c
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                TagInfoFragment.m5986initViews$lambda1$lambda0(TagInfoFragment.this, (TagInfoBean) obj);
            }
        });
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelFragment
    @NotNull
    public InfoModel viewModelInstance() {
        return getViewModel();
    }
}
