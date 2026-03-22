package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import com.jbzd.media.movecartoons.p396ui.dialog.TagsDialog;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import com.qunidayede.supportlibrary.widget.ClearEditText;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p337d.C2861e;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000`\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\r\n\u0002\b\u0005\n\u0002\b\u0003\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\n*\u0002 #\u0018\u00002\u00020\u0001BR\u0012\u000e\u0010\u0019\u001a\n\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u0005\u0012\u000e\u0010\u001e\u001a\n\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u0005\u0012)\b\u0002\u0010)\u001a#\u0012\u0019\u0012\u0017\u0012\u0004\u0012\u00020\u00060\u0005¢\u0006\f\b'\u0012\b\b(\u0012\u0004\b\b(\u001e\u0012\u0004\u0012\u00020\u00100&¢\u0006\u0004\b/\u00100J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0015\u0010\u0007\u001a\b\u0012\u0004\u0012\u00020\u00060\u0005H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\t\u001a\b\u0012\u0004\u0012\u00020\u00060\u0005H\u0002¢\u0006\u0004\b\t\u0010\bJ\u0017\u0010\f\u001a\u00020\u000b2\u0006\u0010\n\u001a\u00020\u0006H\u0002¢\u0006\u0004\b\f\u0010\rJ\u001f\u0010\u0011\u001a\u00020\u00102\u0006\u0010\n\u001a\u00020\u00062\u0006\u0010\u000f\u001a\u00020\u000eH\u0002¢\u0006\u0004\b\u0011\u0010\u0012J\u001f\u0010\u0013\u001a\u00020\u00102\u0006\u0010\n\u001a\u00020\u00062\u0006\u0010\u000f\u001a\u00020\u000eH\u0002¢\u0006\u0004\b\u0013\u0010\u0012J\u0019\u0010\u0017\u001a\u00020\u00162\b\u0010\u0015\u001a\u0004\u0018\u00010\u0014H\u0016¢\u0006\u0004\b\u0017\u0010\u0018J+\u0010\u001c\u001a\b\u0012\u0004\u0012\u00020\u00060\u00052\f\u0010\u0019\u001a\b\u0012\u0004\u0012\u00020\u00060\u00052\b\u0010\u001b\u001a\u0004\u0018\u00010\u001a¢\u0006\u0004\b\u001c\u0010\u001dR\u001e\u0010\u001e\u001a\n\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u00058\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u001e\u0010\u001fR\u001e\u0010\u0019\u001a\n\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u00058\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u0019\u0010\u001fR\u0016\u0010!\u001a\u00020 8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b!\u0010\"R\u0016\u0010$\u001a\u00020#8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b$\u0010%R7\u0010)\u001a#\u0012\u0019\u0012\u0017\u0012\u0004\u0012\u00020\u00060\u0005¢\u0006\f\b'\u0012\b\b(\u0012\u0004\b\b(\u001e\u0012\u0004\u0012\u00020\u00100&8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b)\u0010*R\u001d\u0010.\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b+\u0010,\u001a\u0004\b-\u0010\u0004¨\u00061"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/TagsDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "", "Lcom/jbzd/media/movecartoons/bean/response/tag/TagBean;", "getSelectedTags", "()Ljava/util/List;", "getAllTags", "tag", "", "contain", "(Lcom/jbzd/media/movecartoons/bean/response/tag/TagBean;)Z", "", "position", "", "clickSelectTag", "(Lcom/jbzd/media/movecartoons/bean/response/tag/TagBean;I)V", "clickAllTag", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "allTags", "", "keywords", "filterKeywords", "(Ljava/util/List;Ljava/lang/CharSequence;)Ljava/util/List;", "selectTags", "Ljava/util/List;", "com/jbzd/media/movecartoons/ui/dialog/TagsDialog$mSelectedTagAdapter$1", "mSelectedTagAdapter", "Lcom/jbzd/media/movecartoons/ui/dialog/TagsDialog$mSelectedTagAdapter$1;", "com/jbzd/media/movecartoons/ui/dialog/TagsDialog$mAllTagAdapter$1", "mAllTagAdapter", "Lcom/jbzd/media/movecartoons/ui/dialog/TagsDialog$mAllTagAdapter$1;", "Lkotlin/Function1;", "Lkotlin/ParameterName;", "name", "submitBlock", "Lkotlin/jvm/functions/Function1;", "alertDialog$delegate", "Lkotlin/Lazy;", "getAlertDialog", "alertDialog", "<init>", "(Ljava/util/List;Ljava/util/List;Lkotlin/jvm/functions/Function1;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class TagsDialog extends DialogFragment {

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog;

    @Nullable
    private final List<TagBean> allTags;

    @NotNull
    private final TagsDialog$mAllTagAdapter$1 mAllTagAdapter;

    @NotNull
    private final TagsDialog$mSelectedTagAdapter$1 mSelectedTagAdapter;

    @Nullable
    private final List<TagBean> selectTags;

    @NotNull
    private final Function1<List<? extends TagBean>, Unit> submitBlock;

    public /* synthetic */ TagsDialog(List list, List list2, Function1 function1, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(list, list2, (i2 & 4) != 0 ? new Function1<List<? extends TagBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TagsDialog.1
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends TagBean> list3) {
                invoke2(list3);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull List<? extends TagBean> it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        } : function1);
    }

    private final void clickAllTag(TagBean tag, int position) {
        if (!contain(tag)) {
            if (getSelectedTags().size() >= 8) {
                C2354n.m2449Z("最多选择8个标签");
                return;
            } else {
                addData((TagsDialog$mSelectedTagAdapter$1) tag);
                notifyItemChanged(position);
                return;
            }
        }
        Iterator<TagBean> it = getSelectedTags().iterator();
        int i2 = 0;
        while (true) {
            if (!it.hasNext()) {
                break;
            }
            int i3 = i2 + 1;
            if (TextUtils.equals(it.next().f10032id, tag.f10032id)) {
                remove(i2);
                break;
            }
            i2 = i3;
        }
        notifyItemChanged(position);
    }

    private final void clickSelectTag(TagBean tag, int position) {
        remove(position);
        Iterator<TagBean> it = getAllTags().iterator();
        int i2 = 0;
        while (it.hasNext()) {
            int i3 = i2 + 1;
            if (TextUtils.equals(it.next().f10032id, tag.f10032id)) {
                notifyItemChanged(i2);
                return;
            }
            i2 = i3;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final boolean contain(TagBean tag) {
        Iterator<TagBean> it = getSelectedTags().iterator();
        while (it.hasNext()) {
            if (TextUtils.equals(it.next().f10032id, tag.f10032id)) {
                return true;
            }
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        View inflate = LayoutInflater.from(getContext()).inflate(R.layout.dialog_tags, (ViewGroup) null);
        RecyclerView recyclerView = (RecyclerView) inflate.findViewById(R.id.rv_selected);
        RecyclerView recyclerView2 = (RecyclerView) inflate.findViewById(R.id.rv_tags);
        ImageView imageView = (ImageView) inflate.findViewById(R.id.itv_confirm_post);
        ImageView imageView2 = (ImageView) inflate.findViewById(R.id.iv_close);
        final ClearEditText clearEditText = (ClearEditText) inflate.findViewById(R.id.cet_num);
        View findViewById = inflate.findViewById(R.id.btn_outside);
        clearEditText.addTextChangedListener(new TextWatcher() { // from class: com.jbzd.media.movecartoons.ui.dialog.TagsDialog$createDialog$1
            @Override // android.text.TextWatcher
            public void afterTextChanged(@Nullable Editable s) {
            }

            @Override // android.text.TextWatcher
            public void beforeTextChanged(@Nullable CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(@Nullable CharSequence s, int start, int before, int count) {
                List list;
                TagsDialog$mAllTagAdapter$1 tagsDialog$mAllTagAdapter$1;
                List<? extends TagBean> list2;
                list = TagsDialog.this.allTags;
                if (list != null) {
                    tagsDialog$mAllTagAdapter$1 = TagsDialog.this.mAllTagAdapter;
                    TagsDialog tagsDialog = TagsDialog.this;
                    list2 = tagsDialog.allTags;
                    tagsDialog$mAllTagAdapter$1.setNewData(CollectionsKt___CollectionsKt.toMutableList((Collection) tagsDialog.filterKeywords(list2, s)));
                }
            }
        });
        recyclerView2.setLayoutManager(new GridLayoutManager(recyclerView2.getContext(), 4));
        if (recyclerView2.getItemDecorationCount() == 0) {
            GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(recyclerView2.getContext());
            c4053a.f10336d = C1499a.m638x(c4053a, R.color.transparent, recyclerView2, 7.5d);
            c4053a.f10337e = C2354n.m2437V(recyclerView2.getContext(), 2.5d);
            c4053a.f10339g = false;
            c4053a.f10340h = false;
            c4053a.f10338f = false;
            C1499a.m604Z(c4053a, recyclerView2);
        }
        recyclerView2.setAdapter(this.mAllTagAdapter);
        TagsDialog$mAllTagAdapter$1 tagsDialog$mAllTagAdapter$1 = this.mAllTagAdapter;
        List<TagBean> list = this.allTags;
        tagsDialog$mAllTagAdapter$1.setNewData(list == null ? null : CollectionsKt___CollectionsKt.toMutableList((Collection) list));
        recyclerView.setLayoutManager(new GridLayoutManager(recyclerView.getContext(), 4));
        if (recyclerView.getItemDecorationCount() == 0) {
            GridItemDecoration.C4053a c4053a2 = new GridItemDecoration.C4053a(recyclerView.getContext());
            c4053a2.f10336d = C1499a.m638x(c4053a2, R.color.transparent, recyclerView, 7.5d);
            c4053a2.f10337e = C2354n.m2437V(recyclerView.getContext(), 2.5d);
            c4053a2.f10339g = false;
            c4053a2.f10340h = false;
            c4053a2.f10338f = false;
            C1499a.m604Z(c4053a2, recyclerView);
        }
        recyclerView.setAdapter(this.mSelectedTagAdapter);
        TagsDialog$mSelectedTagAdapter$1 tagsDialog$mSelectedTagAdapter$1 = this.mSelectedTagAdapter;
        List<TagBean> list2 = this.selectTags;
        tagsDialog$mSelectedTagAdapter$1.setNewData(list2 == null ? null : CollectionsKt___CollectionsKt.toMutableList((Collection) list2));
        setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.e.e0
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                TagsDialog.m5793createDialog$lambda2(TagsDialog.this, baseQuickAdapter, view, i2);
            }
        });
        setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.e.d0
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                TagsDialog.m5794createDialog$lambda3(TagsDialog.this, baseQuickAdapter, view, i2);
            }
        });
        C2354n.m2374A(imageView, 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TagsDialog$createDialog$6
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView3) {
                invoke2(imageView3);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(ImageView imageView3) {
                Function1 function1;
                List selectedTags;
                TagsDialog.this.dismiss();
                function1 = TagsDialog.this.submitBlock;
                selectedTags = TagsDialog.this.getSelectedTags();
                function1.invoke(selectedTags);
            }
        }, 1);
        C2354n.m2374A(imageView2, 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TagsDialog$createDialog$7
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView3) {
                invoke2(imageView3);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(ImageView imageView3) {
                TagsDialog.this.dismiss();
            }
        }, 1);
        C2354n.m2374A(findViewById, 0L, new Function1<View, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TagsDialog$createDialog$8
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(View view) {
                invoke2(view);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(View view) {
                C2861e.m3306d(ClearEditText.this);
                this.dismiss();
            }
        }, 1);
        AlertDialog create = new AlertDialog.Builder(requireContext(), 2131951873).setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: b.a.a.a.t.e.c0
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                C2861e.m3306d(ClearEditText.this);
            }
        }).setView(inflate).create();
        Intrinsics.checkNotNullExpressionValue(create, "Builder(requireContext(), R.style.Dialog_FullScreen_BottomIn)\n            .setOnDismissListener {\n                KeyboardUtils.hideSoftInput(cet_num)\n            }\n            .setView(contentView)\n            .create()");
        return create;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: createDialog$lambda-2, reason: not valid java name */
    public static final void m5793createDialog$lambda2(TagsDialog this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.tag.TagBean");
        this$0.clickAllTag((TagBean) obj, i2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: createDialog$lambda-3, reason: not valid java name */
    public static final void m5794createDialog$lambda3(TagsDialog this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.tag.TagBean");
        this$0.clickSelectTag((TagBean) obj, i2);
    }

    private final AlertDialog getAlertDialog() {
        return (AlertDialog) this.alertDialog.getValue();
    }

    private final List<TagBean> getAllTags() {
        return getData();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final List<TagBean> getSelectedTags() {
        return getData();
    }

    public void _$_clearFindViewByIdCache() {
    }

    /* JADX WARN: Multi-variable type inference failed */
    @NotNull
    public final List<TagBean> filterKeywords(@NotNull List<? extends TagBean> allTags, @Nullable CharSequence keywords) {
        Intrinsics.checkNotNullParameter(allTags, "allTags");
        if (keywords == null || keywords.length() == 0) {
            return allTags;
        }
        ArrayList arrayList = new ArrayList();
        for (TagBean tagBean : allTags) {
            String str = tagBean.name;
            boolean contains = str == null ? false : StringsKt__StringsKt.contains((CharSequence) str, keywords, true);
            String str2 = tagBean.first_letter;
            boolean contains2 = str2 == null ? false : StringsKt__StringsKt.contains((CharSequence) str2, keywords, true);
            if (contains || contains2) {
                arrayList.add(tagBean);
            }
        }
        return arrayList;
    }

    @Override // androidx.fragment.app.DialogFragment
    @NotNull
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        return getAlertDialog();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v3, types: [com.jbzd.media.movecartoons.ui.dialog.TagsDialog$mAllTagAdapter$1] */
    /* JADX WARN: Type inference failed for: r2v4, types: [com.jbzd.media.movecartoons.ui.dialog.TagsDialog$mSelectedTagAdapter$1] */
    public TagsDialog(@Nullable List<? extends TagBean> list, @Nullable List<? extends TagBean> list2, @NotNull Function1<? super List<? extends TagBean>, Unit> submitBlock) {
        Intrinsics.checkNotNullParameter(submitBlock, "submitBlock");
        this.allTags = list;
        this.selectTags = list2;
        this.submitBlock = submitBlock;
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TagsDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = TagsDialog.this.createDialog();
                return createDialog;
            }
        });
        this.mAllTagAdapter = new BaseQuickAdapter<TagBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TagsDialog$mAllTagAdapter$1
            {
                super(R.layout.item_home_tag, null, 2, null);
            }

            @Override // com.chad.library.adapter.base.BaseQuickAdapter
            public void convert(@NotNull BaseViewHolder helper, @NotNull TagBean item) {
                boolean contain;
                boolean contain2;
                boolean contain3;
                Intrinsics.checkNotNullParameter(helper, "helper");
                Intrinsics.checkNotNullParameter(item, "item");
                TagsDialog tagsDialog = TagsDialog.this;
                String str = item.name;
                if (str == null) {
                    str = "";
                }
                helper.m3919i(R.id.tv_name, str);
                TextView textView = (TextView) helper.m3912b(R.id.tv_name);
                contain = tagsDialog.contain(item);
                textView.setSelected(contain);
                LinearLayout linearLayout = (LinearLayout) helper.m3912b(R.id.ll_parent);
                contain2 = tagsDialog.contain(item);
                linearLayout.setSelected(contain2);
                ImageView imageView = (ImageView) helper.m3912b(R.id.iv_del);
                contain3 = tagsDialog.contain(item);
                imageView.setVisibility(contain3 ? 0 : 8);
            }
        };
        this.mSelectedTagAdapter = new BaseQuickAdapter<TagBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TagsDialog$mSelectedTagAdapter$1
            @Override // com.chad.library.adapter.base.BaseQuickAdapter
            public void convert(@NotNull BaseViewHolder helper, @NotNull TagBean item) {
                Intrinsics.checkNotNullParameter(helper, "helper");
                Intrinsics.checkNotNullParameter(item, "item");
                String str = item.name;
                if (str == null) {
                    str = "";
                }
                helper.m3919i(R.id.tv_name, str);
                ((TextView) helper.m3912b(R.id.tv_name)).setSelected(true);
                ((LinearLayout) helper.m3912b(R.id.ll_parent)).setSelected(true);
                ((ImageView) helper.m3912b(R.id.iv_del)).setVisibility(0);
            }
        };
    }
}
