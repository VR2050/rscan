package com.jbzd.media.movecartoons.p396ui.post;

import android.text.TextUtils;
import android.view.View;
import android.widget.ImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.fragment.app.FragmentActivity;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.google.android.flexbox.FlexboxLayoutManager;
import com.jbzd.media.movecartoons.bean.response.TagSubBean;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000t\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u000b\u0018\u0000 >2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001>B\u0007¢\u0006\u0004\b<\u0010=J\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\u0017\u0010\b\u001a\u00020\u00072\u0006\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\b\u0010\tJ\u0017\u0010\n\u001a\u00020\u00072\u0006\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\n\u0010\tJ\u000f\u0010\f\u001a\u00020\u000bH\u0016¢\u0006\u0004\b\f\u0010\rJ\u0011\u0010\u000f\u001a\u0004\u0018\u00010\u000eH\u0016¢\u0006\u0004\b\u000f\u0010\u0010J\u001d\u0010\u0013\u001a\u0012\u0012\u0004\u0012\u00020\u00020\u0011j\b\u0012\u0004\u0012\u00020\u0002`\u0012¢\u0006\u0004\b\u0013\u0010\u0014J\u000f\u0010\u0016\u001a\u00020\u0015H\u0016¢\u0006\u0004\b\u0016\u0010\u0017J\u001f\u0010\u001a\u001a\u00020\u00072\u0006\u0010\u0019\u001a\u00020\u00182\u0006\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u001a\u0010\u001bJ\u0015\u0010\u001e\u001a\u00020\u00072\u0006\u0010\u001d\u001a\u00020\u001c¢\u0006\u0004\b\u001e\u0010\u001fJ3\u0010%\u001a\u00020\u00072\u0012\u0010!\u001a\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00180 2\u0006\u0010#\u001a\u00020\"2\u0006\u0010$\u001a\u00020\u0015H\u0016¢\u0006\u0004\b%\u0010&J\u000f\u0010'\u001a\u00020\u0004H\u0016¢\u0006\u0004\b'\u0010(J\u0011\u0010*\u001a\u0004\u0018\u00010)H\u0016¢\u0006\u0004\b*\u0010+R-\u0010/\u001a\u0012\u0012\u0004\u0012\u00020\u00020\u0011j\b\u0012\u0004\u0012\u00020\u0002`\u00128B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b,\u0010-\u001a\u0004\b.\u0010\u0014R-\u00102\u001a\u0012\u0012\u0004\u0012\u00020\u00020\u0011j\b\u0012\u0004\u0012\u00020\u0002`\u00128B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b0\u0010-\u001a\u0004\b1\u0010\u0014R9\u00108\u001a\u001e\u0012\u0004\u0012\u00020\u001c\u0012\u0004\u0012\u00020\u001c03j\u000e\u0012\u0004\u0012\u00020\u001c\u0012\u0004\u0012\u00020\u001c`48B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b5\u0010-\u001a\u0004\b6\u00107R-\u0010;\u001a\u0012\u0012\u0004\u0012\u00020\u00020\u0011j\b\u0012\u0004\u0012\u00020\u0002`\u00128B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b9\u0010-\u001a\u0004\b:\u0010\u0014¨\u0006?"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/SelectVideoTagsFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/TagSubBean;", "item", "", "contain", "(Lcom/jbzd/media/movecartoons/bean/response/TagSubBean;)Z", "", "remove", "(Lcom/jbzd/media/movecartoons/bean/response/TagSubBean;)V", "add", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLayoutManager", "()Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getItemDecoration", "()Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "Ljava/util/ArrayList;", "Lkotlin/collections/ArrayList;", "getSelects", "()Ljava/util/ArrayList;", "", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/TagSubBean;)V", "", "tagcontent", "refreshTagsList", "(Ljava/lang/String;)V", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "adapter", "Landroid/view/View;", "view", "position", "onItemClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)V", "getLoadMoreEnable", "()Z", "Lc/a/d1;", "request", "()Lc/a/d1;", "allTags$delegate", "Lkotlin/Lazy;", "getAllTags", "allTags", "selectedTags$delegate", "getSelectedTags", "selectedTags", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", "body$delegate", "getBody", "()Ljava/util/HashMap;", "body", "searchTags$delegate", "getSearchTags", "searchTags", "<init>", "()V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SelectVideoTagsFragment extends BaseListFragment<TagSubBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @Nullable
    private static ArrayList<TagSubBean> allTagss;

    @Nullable
    private static ArrayList<TagSubBean> tags;

    /* renamed from: selectedTags$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy selectedTags = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<TagSubBean>>() { // from class: com.jbzd.media.movecartoons.ui.post.SelectVideoTagsFragment$selectedTags$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<TagSubBean> invoke() {
            ArrayList<TagSubBean> arrayList = new ArrayList<>();
            ArrayList<TagSubBean> tags2 = SelectVideoTagsFragment.INSTANCE.getTags();
            if (tags2 != null) {
                Iterator<T> it = tags2.iterator();
                while (it.hasNext()) {
                    arrayList.add((TagSubBean) it.next());
                }
            }
            return arrayList;
        }
    });

    /* renamed from: allTags$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy allTags = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<TagSubBean>>() { // from class: com.jbzd.media.movecartoons.ui.post.SelectVideoTagsFragment$allTags$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<TagSubBean> invoke() {
            ArrayList<TagSubBean> arrayList = new ArrayList<>();
            ArrayList<TagSubBean> allTagss2 = SelectVideoTagsFragment.INSTANCE.getAllTagss();
            if (allTagss2 != null) {
                Iterator<T> it = allTagss2.iterator();
                while (it.hasNext()) {
                    arrayList.add((TagSubBean) it.next());
                }
            }
            return arrayList;
        }
    });

    /* renamed from: searchTags$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy searchTags = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<TagSubBean>>() { // from class: com.jbzd.media.movecartoons.ui.post.SelectVideoTagsFragment$searchTags$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<TagSubBean> invoke() {
            return new ArrayList<>();
        }
    });

    /* renamed from: body$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy body = LazyKt__LazyJVMKt.lazy(new Function0<HashMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.post.SelectVideoTagsFragment$body$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final HashMap<String, String> invoke() {
            return new HashMap<>();
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u000e\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0013\u0010\u0014JE\u0010\b\u001a\u00020\u00072\u001a\u0010\u0005\u001a\u0016\u0012\u0004\u0012\u00020\u0003\u0018\u00010\u0002j\n\u0012\u0004\u0012\u00020\u0003\u0018\u0001`\u00042\u001a\u0010\u0006\u001a\u0016\u0012\u0004\u0012\u00020\u0003\u0018\u00010\u0002j\n\u0012\u0004\u0012\u00020\u0003\u0018\u0001`\u0004¢\u0006\u0004\b\b\u0010\tR6\u0010\n\u001a\u0016\u0012\u0004\u0012\u00020\u0003\u0018\u00010\u0002j\n\u0012\u0004\u0012\u00020\u0003\u0018\u0001`\u00048\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\n\u0010\u000b\u001a\u0004\b\f\u0010\r\"\u0004\b\u000e\u0010\u000fR6\u0010\u0010\u001a\u0016\u0012\u0004\u0012\u00020\u0003\u0018\u00010\u0002j\n\u0012\u0004\u0012\u00020\u0003\u0018\u0001`\u00048\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0010\u0010\u000b\u001a\u0004\b\u0011\u0010\r\"\u0004\b\u0012\u0010\u000f¨\u0006\u0015"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/SelectVideoTagsFragment$Companion;", "", "Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/bean/response/TagSubBean;", "Lkotlin/collections/ArrayList;", "selectedTags", "allTags", "Lcom/jbzd/media/movecartoons/ui/post/SelectVideoTagsFragment;", "newInstance", "(Ljava/util/ArrayList;Ljava/util/ArrayList;)Lcom/jbzd/media/movecartoons/ui/post/SelectVideoTagsFragment;", "tags", "Ljava/util/ArrayList;", "getTags", "()Ljava/util/ArrayList;", "setTags", "(Ljava/util/ArrayList;)V", "allTagss", "getAllTagss", "setAllTagss", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @Nullable
        public final ArrayList<TagSubBean> getAllTagss() {
            return SelectVideoTagsFragment.allTagss;
        }

        @Nullable
        public final ArrayList<TagSubBean> getTags() {
            return SelectVideoTagsFragment.tags;
        }

        @NotNull
        public final SelectVideoTagsFragment newInstance(@Nullable ArrayList<TagSubBean> selectedTags, @Nullable ArrayList<TagSubBean> allTags) {
            setTags(selectedTags);
            setAllTagss(allTags);
            return new SelectVideoTagsFragment();
        }

        public final void setAllTagss(@Nullable ArrayList<TagSubBean> arrayList) {
            SelectVideoTagsFragment.allTagss = arrayList;
        }

        public final void setTags(@Nullable ArrayList<TagSubBean> arrayList) {
            SelectVideoTagsFragment.tags = arrayList;
        }
    }

    private final void add(TagSubBean item) {
        if (getSelectedTags().size() >= 3) {
            C2354n.m2449Z("最多选择3个!");
        } else {
            getSelectedTags().add(item);
            getAdapter().notifyDataSetChanged();
        }
    }

    private final boolean contain(TagSubBean item) {
        Iterator<TagSubBean> it = getSelectedTags().iterator();
        while (it.hasNext()) {
            if (TextUtils.equals(it.next().getId(), item.getId())) {
                return true;
            }
        }
        return false;
    }

    private final ArrayList<TagSubBean> getAllTags() {
        return (ArrayList) this.allTags.getValue();
    }

    private final HashMap<String, String> getBody() {
        return (HashMap) this.body.getValue();
    }

    private final ArrayList<TagSubBean> getSearchTags() {
        return (ArrayList) this.searchTags.getValue();
    }

    private final ArrayList<TagSubBean> getSelectedTags() {
        return (ArrayList) this.selectedTags.getValue();
    }

    private final void remove(TagSubBean item) {
        Iterator<TagSubBean> it = getSelectedTags().iterator();
        int i2 = 0;
        while (true) {
            if (!it.hasNext()) {
                i2 = -1;
                break;
            }
            int i3 = i2 + 1;
            if (TextUtils.equals(it.next().getId(), item.getId())) {
                break;
            } else {
                i2 = i3;
            }
        }
        if (i2 >= 0) {
            getSelectedTags().remove(i2);
        }
        getAdapter().notifyDataSetChanged();
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public RecyclerView.ItemDecoration getItemDecoration() {
        GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(getContext());
        c4053a.m4576a(R.color.transparent);
        c4053a.f10336d = C2354n.m2437V(getContext(), 5.0d);
        c4053a.f10337e = C2354n.m2437V(getContext(), 5.0d);
        return new GridItemDecoration(c4053a);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.item_video_tag;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public RecyclerView.LayoutManager getLayoutManager() {
        FlexboxLayoutManager flexboxLayoutManager = new FlexboxLayoutManager(getContext());
        flexboxLayoutManager.m4176y(1);
        flexboxLayoutManager.m4175x(0);
        return flexboxLayoutManager;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public boolean getLoadMoreEnable() {
        return false;
    }

    @NotNull
    public final ArrayList<TagSubBean> getSelects() {
        return getSelectedTags();
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void onItemClick(@NotNull BaseQuickAdapter<TagSubBean, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        super.onItemClick(adapter, view, position);
        TagSubBean tagSubBean = adapter.getData().get(position);
        if (contain(tagSubBean)) {
            remove(tagSubBean);
        } else {
            add(tagSubBean);
        }
        FragmentActivity activity = getActivity();
        if (activity instanceof PostVideoTagChooseActivity) {
            if (getSelectedTags().size() > 0) {
                ((PostVideoTagChooseActivity) activity).setRightTitle(getSelectedTags().size() + "/3");
                return;
            }
            ((PostVideoTagChooseActivity) activity).setRightTitle(getSelectedTags().size() + "/3");
        }
    }

    public final void refreshTagsList(@NotNull String tagcontent) {
        Intrinsics.checkNotNullParameter(tagcontent, "tagcontent");
        if (tagcontent.equals("")) {
            getAdapter().setNewData(getAllTags());
            return;
        }
        if (getSearchTags().size() > 0) {
            getSearchTags().clear();
        }
        ArrayList<TagSubBean> allTags = getAllTags();
        Intrinsics.checkNotNull(allTags);
        Iterator<TagSubBean> it = allTags.iterator();
        while (it.hasNext()) {
            TagSubBean next = it.next();
            String name = next.getName();
            Intrinsics.checkNotNullExpressionValue(name, "tag.name");
            if (StringsKt__StringsKt.contains$default((CharSequence) name, (CharSequence) tagcontent, false, 2, (Object) null)) {
                getSearchTags().add(next);
            }
        }
        if (getSearchTags().size() > 0) {
            getAdapter().setNewData(getSearchTags());
        } else {
            getAdapter().setNewData(null);
            getAdapter().setEmptyView(R.layout.empty_view);
        }
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public InterfaceC3053d1 request() {
        showLoadingDialog("Loading...", true);
        getAdapter().setNewData(getAllTags());
        return C0917a.m222f(C0917a.f372a, "movie/tags", TagSubBean.class, getBody(), new Function1<List<? extends TagSubBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.SelectVideoTagsFragment$request$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends TagSubBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends TagSubBean> list) {
                SelectVideoTagsFragment.this.hideLoadingDialog();
                SelectVideoTagsFragment.this.didRequestComplete(list);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.SelectVideoTagsFragment$request$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                SelectVideoTagsFragment.this.hideLoadingDialog();
                SelectVideoTagsFragment.this.didRequestError();
            }
        }, false, false, null, false, 480);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull TagSubBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        ImageView imageView = (ImageView) helper.m3912b(R.id.iv_select);
        ConstraintLayout constraintLayout = (ConstraintLayout) helper.m3912b(R.id.ll_item);
        imageView.setVisibility(8);
        imageView.setSelected(contain(item));
        constraintLayout.setSelected(contain(item));
        helper.m3919i(R.id.tv_posttopic_name, String.valueOf(item.getName()));
    }
}
