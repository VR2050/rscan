package com.jbzd.media.movecartoons.p396ui.comics;

import android.content.res.Resources;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.core.app.NotificationCompat;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentViewModelLazyKt;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelStore;
import androidx.lifecycle.ViewModelStoreOwner;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.CommentListBean;
import com.jbzd.media.movecartoons.bean.response.ChatMsgBean;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import com.jbzd.media.movecartoons.p396ui.comics.CommentFragment;
import com.jbzd.media.movecartoons.p396ui.comics.CommentFragment$postCommentListAdapter$2;
import com.jbzd.media.movecartoons.p396ui.post.PostViewModel;
import com.jbzd.media.movecartoons.view.decoration.ItemDecorationV;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Collection;
import java.util.HashMap;
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
import kotlin.jvm.internal.Reflection;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.json.JSONObject;
import p005b.p006a.p007a.p008a.p009a.C0843e0;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.C1558h;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p336c.C2851b;
import p005b.p327w.p330b.p336c.C2852c;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000[\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0013\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\b\u0014*\u0001:\u0018\u0000 L2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001LB\u0007¢\u0006\u0004\bK\u0010\u0018J\u0019\u0010\u0005\u001a\u00020\u00032\b\u0010\u0004\u001a\u0004\u0018\u00010\u0003H\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\r\u0010\b\u001a\u00020\u0007¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\u000b\u001a\u00020\nH\u0016¢\u0006\u0004\b\u000b\u0010\fJ\u001f\u0010\u0011\u001a\u00020\u00102\u0006\u0010\u000e\u001a\u00020\r2\u0006\u0010\u000f\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0011\u0010\u0012J\u0011\u0010\u0014\u001a\u0004\u0018\u00010\u0013H\u0016¢\u0006\u0004\b\u0014\u0010\u0015J\u000f\u0010\u0016\u001a\u00020\nH\u0016¢\u0006\u0004\b\u0016\u0010\fJ\u000f\u0010\u0017\u001a\u00020\u0010H\u0016¢\u0006\u0004\b\u0017\u0010\u0018J\u0015\u0010\u001a\u001a\u00020\u00102\u0006\u0010\u0019\u001a\u00020\u0003¢\u0006\u0004\b\u001a\u0010\u001bR\u001d\u0010!\u001a\u00020\u001c8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001d\u0010\u001e\u001a\u0004\b\u001f\u0010 R\"\u0010\"\u001a\u00020\u00038\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\"\u0010#\u001a\u0004\b$\u0010%\"\u0004\b&\u0010\u001bR\u001d\u0010)\u001a\u00020\u00038B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b'\u0010\u001e\u001a\u0004\b(\u0010%R\u001d\u0010,\u001a\u00020\u00078F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b*\u0010\u001e\u001a\u0004\b+\u0010\tR\u001d\u0010/\u001a\u00020\u00038B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b-\u0010\u001e\u001a\u0004\b.\u0010%R\u001d\u00104\u001a\u0002008F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b1\u0010\u001e\u001a\u0004\b2\u00103R\u001d\u00109\u001a\u0002058F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b6\u0010\u001e\u001a\u0004\b7\u00108R\u001d\u0010>\u001a\u00020:8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b;\u0010\u001e\u001a\u0004\b<\u0010=R\"\u0010?\u001a\u00020\u00038\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b?\u0010#\u001a\u0004\b@\u0010%\"\u0004\bA\u0010\u001bR\u001d\u0010D\u001a\u0002008F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bB\u0010\u001e\u001a\u0004\bC\u00103R\u001d\u0010G\u001a\u0002058F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bE\u0010\u001e\u001a\u0004\bF\u00108R\"\u0010H\u001a\u00020\u00038\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bH\u0010#\u001a\u0004\bI\u0010%\"\u0004\bJ\u0010\u001b¨\u0006M"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/comics/CommentFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/CommentListBean;", "", "love", "getShowLoveTxt", "(Ljava/lang/String;)Ljava/lang/String;", "Lcom/jbzd/media/movecartoons/ui/post/PostViewModel;", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/post/PostViewModel;", "", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/CommentListBean;)V", "Lc/a/d1;", "request", "()Lc/a/d1;", "getLayout", "initEvents", "()V", "contentComment", "sendCommentOut", "(Ljava/lang/String;)V", "Landroid/view/View;", "ll_bottom_tool$delegate", "Lkotlin/Lazy;", "getLl_bottom_tool", "()Landroid/view/View;", "ll_bottom_tool", "type_comment", "Ljava/lang/String;", "getType_comment", "()Ljava/lang/String;", "setType_comment", "mId$delegate", "getMId", "mId", "mPostViewModel$delegate", "getMPostViewModel", "mPostViewModel", "mType$delegate", "getMType", "mType", "Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_confirm_post$delegate", "getItv_confirm_post", "()Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_confirm_post", "Landroidx/appcompat/widget/AppCompatEditText;", "ed_input_comment$delegate", "getEd_input_comment", "()Landroidx/appcompat/widget/AppCompatEditText;", "ed_input_comment", "com/jbzd/media/movecartoons/ui/comics/CommentFragment$postCommentListAdapter$2$1", "postCommentListAdapter$delegate", "getPostCommentListAdapter", "()Lcom/jbzd/media/movecartoons/ui/comics/CommentFragment$postCommentListAdapter$2$1;", "postCommentListAdapter", "type_post", "getType_post", "setType_post", "itv_favorite$delegate", "getItv_favorite", "itv_favorite", "tv_input_comment$delegate", "getTv_input_comment", "tv_input_comment", "id_comment", "getId_comment", "setId_comment", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class CommentFragment extends BaseListFragment<CommentListBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: ed_input_comment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ed_input_comment;

    /* renamed from: itv_confirm_post$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_confirm_post;

    /* renamed from: itv_favorite$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_favorite;

    /* renamed from: ll_bottom_tool$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_bottom_tool;

    /* renamed from: mId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mId;

    /* renamed from: mPostViewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mPostViewModel;

    /* renamed from: mType$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mType;

    /* renamed from: postCommentListAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy postCommentListAdapter;

    /* renamed from: tv_input_comment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_input_comment;

    @NotNull
    private String id_comment = "id";

    @NotNull
    private String type_comment = "type";

    @NotNull
    private String type_post = "";

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\b\u0010\tJ\u001d\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0004\u001a\u00020\u0002¢\u0006\u0004\b\u0006\u0010\u0007¨\u0006\n"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/comics/CommentFragment$Companion;", "", "", "id", "type", "Lcom/jbzd/media/movecartoons/ui/comics/CommentFragment;", "newInstance", "(Ljava/lang/String;Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/comics/CommentFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final CommentFragment newInstance(@NotNull String id, @NotNull String type) {
            Intrinsics.checkNotNullParameter(id, "id");
            Intrinsics.checkNotNullParameter(type, "type");
            CommentFragment commentFragment = new CommentFragment();
            Bundle bundle = new Bundle();
            bundle.putString(commentFragment.getId_comment(), id);
            bundle.putString(commentFragment.getType_comment(), type);
            Unit unit = Unit.INSTANCE;
            commentFragment.setArguments(bundle);
            return commentFragment;
        }
    }

    public CommentFragment() {
        final Function0<Fragment> function0 = new Function0<Fragment>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$special$$inlined$viewModels$default$1
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
        this.mPostViewModel = FragmentViewModelLazyKt.createViewModelLazy(this, Reflection.getOrCreateKotlinClass(PostViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$special$$inlined$viewModels$default$2
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
        this.mId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$mId$2
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final String invoke() {
                Bundle arguments = CommentFragment.this.getArguments();
                String string = arguments == null ? null : arguments.getString(CommentFragment.this.getId_comment());
                Objects.requireNonNull(string, "null cannot be cast to non-null type kotlin.String");
                return string;
            }
        });
        this.mType = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$mType$2
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final String invoke() {
                Bundle arguments = CommentFragment.this.getArguments();
                String string = arguments == null ? null : arguments.getString(CommentFragment.this.getType_comment());
                Objects.requireNonNull(string, "null cannot be cast to non-null type kotlin.String");
                return string;
            }
        });
        this.tv_input_comment = LazyKt__LazyJVMKt.lazy(new Function0<AppCompatEditText>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$tv_input_comment$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AppCompatEditText invoke() {
                View view = CommentFragment.this.getView();
                AppCompatEditText appCompatEditText = view == null ? null : (AppCompatEditText) view.findViewById(R.id.tv_input_comment);
                Intrinsics.checkNotNull(appCompatEditText);
                return appCompatEditText;
            }
        });
        this.postCommentListAdapter = LazyKt__LazyJVMKt.lazy(new Function0<CommentFragment$postCommentListAdapter$2.C36801>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$postCommentListAdapter$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            /* JADX WARN: Type inference failed for: r0v0, types: [com.jbzd.media.movecartoons.ui.comics.CommentFragment$postCommentListAdapter$2$1] */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final C36801 invoke() {
                final CommentFragment commentFragment = CommentFragment.this;
                return new BaseQuickAdapter<CommentListBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$postCommentListAdapter$2.1
                    {
                        super(R.layout.item_post_comment, null, 2, null);
                    }

                    @Override // com.chad.library.adapter.base.BaseQuickAdapter
                    public void convert(@NotNull final BaseViewHolder helper, @NotNull final CommentListBean item) {
                        String showLoveTxt;
                        Resources resources;
                        int i2;
                        Intrinsics.checkNotNullParameter(helper, "helper");
                        Intrinsics.checkNotNullParameter(item, "item");
                        final CommentFragment commentFragment2 = CommentFragment.this;
                        C2852c m2455a2 = C2354n.m2455a2(commentFragment2.requireContext());
                        String str = item.img;
                        if (str == null) {
                            str = "";
                        }
                        C1558h mo770c = m2455a2.mo770c();
                        mo770c.mo763X(str);
                        ((C2851b) mo770c).m3292f0().m757R((ImageView) helper.m3912b(R.id.iv_post_comment_userheder));
                        TextView textView = (TextView) helper.m3912b(R.id.tv_post_username);
                        TextView textView2 = (TextView) helper.m3912b(R.id.tv_post_comment_content);
                        TextView textView3 = (TextView) helper.m3912b(R.id.tv_post_comment_time);
                        ImageTextView imageTextView = (ImageTextView) helper.m3912b(R.id.itv_postcomment_likes);
                        TextView textView4 = (TextView) helper.m3912b(R.id.tv_post_comment_reply);
                        if (Intrinsics.areEqual(item.user_id, ChatMsgBean.SERVICE_ID)) {
                            imageTextView.setVisibility(8);
                            textView4.setVisibility(8);
                        } else {
                            imageTextView.setVisibility(0);
                            textView4.setVisibility(0);
                        }
                        textView.setText(item.nickname);
                        textView2.setText(item.content);
                        textView3.setText(item.label);
                        showLoveTxt = commentFragment2.getShowLoveTxt(item.love);
                        imageTextView.setText(showLoveTxt);
                        if (Intrinsics.areEqual(item.love, "0") && Intrinsics.areEqual(item.has_love, "y")) {
                            imageTextView.setText("已赞");
                        }
                        imageTextView.setSelected(Intrinsics.areEqual(item.has_love, "y"));
                        if (Intrinsics.areEqual(item.has_love, "y")) {
                            resources = commentFragment2.getResources();
                            i2 = R.color.color_red_ff3f3f;
                        } else {
                            resources = commentFragment2.getResources();
                            i2 = R.color.color_comment;
                        }
                        helper.m3920j(R.id.itv_postcomment_likes, resources.getColor(i2));
                        C2354n.m2374A(imageTextView, 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$postCommentListAdapter$2$1$convert$1$1
                            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                            {
                                super(1);
                            }

                            @Override // kotlin.jvm.functions.Function1
                            public /* bridge */ /* synthetic */ Unit invoke(ImageTextView imageTextView2) {
                                invoke2(imageTextView2);
                                return Unit.INSTANCE;
                            }

                            /* renamed from: invoke, reason: avoid collision after fix types in other method */
                            public final void invoke2(@NotNull ImageTextView it) {
                                Intrinsics.checkNotNullParameter(it, "it");
                                getItem(helper.getPosition()).setHas_love(Intrinsics.areEqual(getItem(helper.getPosition()).has_love, "y") ? "n" : "y");
                                if (Intrinsics.areEqual(getItem(helper.getPosition()).love, "1") && Intrinsics.areEqual(getItem(helper.getPosition()).has_love, "n")) {
                                    getItem(helper.getPosition()).love = "0";
                                }
                                notifyItemChanged(helper.getPosition());
                                PostViewModel mPostViewModel = commentFragment2.getMPostViewModel();
                                String str2 = item.f9922id;
                                Intrinsics.checkNotNullExpressionValue(str2, "item.id");
                                final CommentFragment commentFragment3 = commentFragment2;
                                mPostViewModel.commentDoLove(str2, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$postCommentListAdapter$2$1$convert$1$1.1
                                    {
                                        super(1);
                                    }

                                    @Override // kotlin.jvm.functions.Function1
                                    public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                                        invoke(bool.booleanValue());
                                        return Unit.INSTANCE;
                                    }

                                    public final void invoke(boolean z) {
                                        CommentFragment.this.hideLoadingDialog();
                                    }
                                });
                            }
                        }, 1);
                    }
                };
            }
        });
        this.ll_bottom_tool = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$ll_bottom_tool$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final View invoke() {
                View view = CommentFragment.this.getView();
                View findViewById = view == null ? null : view.findViewById(R.id.ll_bottom_tool);
                Intrinsics.checkNotNull(findViewById);
                return findViewById;
            }
        });
        this.itv_favorite = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$itv_favorite$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ImageTextView invoke() {
                View view = CommentFragment.this.getView();
                ImageTextView imageTextView = view == null ? null : (ImageTextView) view.findViewById(R.id.itv_favorite);
                Intrinsics.checkNotNull(imageTextView);
                return imageTextView;
            }
        });
        this.itv_confirm_post = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$itv_confirm_post$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ImageTextView invoke() {
                View view = CommentFragment.this.getView();
                ImageTextView imageTextView = view == null ? null : (ImageTextView) view.findViewById(R.id.itv_confirm_post);
                Intrinsics.checkNotNull(imageTextView);
                return imageTextView;
            }
        });
        this.ed_input_comment = LazyKt__LazyJVMKt.lazy(new Function0<AppCompatEditText>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$ed_input_comment$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AppCompatEditText invoke() {
                View view = CommentFragment.this.getView();
                AppCompatEditText appCompatEditText = view == null ? null : (AppCompatEditText) view.findViewById(R.id.ed_input_comment);
                Intrinsics.checkNotNull(appCompatEditText);
                return appCompatEditText;
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getMId() {
        return (String) this.mId.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getMType() {
        return (String) this.mType.getValue();
    }

    private final CommentFragment$postCommentListAdapter$2.C36801 getPostCommentListAdapter() {
        return (CommentFragment$postCommentListAdapter$2.C36801) this.postCommentListAdapter.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getShowLoveTxt(String love) {
        return ((love == null || StringsKt__StringsJVMKt.isBlank(love)) || TextUtils.equals("0", love)) ? "点赞" : C0843e0.m182a(love);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initEvents$lambda-5$lambda-4, reason: not valid java name */
    public static final void m5765initEvents$lambda5$lambda4(CommentFragment this$0, List it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        RecyclerView rv_content = this$0.getRv_content();
        rv_content.setAdapter(this$0.getPostCommentListAdapter());
        CommentFragment$postCommentListAdapter$2.C36801 postCommentListAdapter = this$0.getPostCommentListAdapter();
        Intrinsics.checkNotNullExpressionValue(it, "it");
        postCommentListAdapter.setNewData(CollectionsKt___CollectionsKt.toMutableList((Collection) it));
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(this$0.requireContext());
        linearLayoutManager.setOrientation(1);
        Unit unit = Unit.INSTANCE;
        rv_content.setLayoutManager(linearLayoutManager);
        if (rv_content.getItemDecorationCount() == 0) {
            rv_content.addItemDecoration(new ItemDecorationV(C2354n.m2425R(this$0.requireContext(), 2.0f), C2354n.m2425R(this$0.requireContext(), 2.0f)));
        }
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final AppCompatEditText getEd_input_comment() {
        return (AppCompatEditText) this.ed_input_comment.getValue();
    }

    @NotNull
    public final String getId_comment() {
        return this.id_comment;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.item_post_comment;
    }

    @NotNull
    public final ImageTextView getItv_confirm_post() {
        return (ImageTextView) this.itv_confirm_post.getValue();
    }

    @NotNull
    public final ImageTextView getItv_favorite() {
        return (ImageTextView) this.itv_favorite.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.frag_comment;
    }

    @NotNull
    public final View getLl_bottom_tool() {
        return (View) this.ll_bottom_tool.getValue();
    }

    @NotNull
    public final PostViewModel getMPostViewModel() {
        return (PostViewModel) this.mPostViewModel.getValue();
    }

    @NotNull
    public final AppCompatEditText getTv_input_comment() {
        return (AppCompatEditText) this.tv_input_comment.getValue();
    }

    @NotNull
    public final String getType_comment() {
        return this.type_comment;
    }

    @NotNull
    public final String getType_post() {
        return this.type_post;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initEvents() {
        if (Intrinsics.areEqual(getMType(), "movie")) {
            getLl_bottom_tool().setVisibility(0);
            getItv_favorite().setVisibility(8);
        } else {
            getItv_favorite().setVisibility(0);
        }
        final PostViewModel mPostViewModel = getMPostViewModel();
        mPostViewModel.getMCommentListBean().observe(this, new Observer() { // from class: b.a.a.a.t.d.n
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                CommentFragment.m5765initEvents$lambda5$lambda4(CommentFragment.this, (List) obj);
            }
        });
        C2354n.m2374A(getItv_favorite(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$initEvents$1$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageTextView imageTextView) {
                invoke2(imageTextView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageTextView it) {
                String mType;
                String mId;
                String mId2;
                Intrinsics.checkNotNullParameter(it, "it");
                mType = CommentFragment.this.getMType();
                if (Intrinsics.areEqual(mType, "comics")) {
                    PostViewModel mPostViewModel2 = CommentFragment.this.getMPostViewModel();
                    mId2 = CommentFragment.this.getMId();
                    final CommentFragment commentFragment = CommentFragment.this;
                    PostViewModel.comicsDoFavorite$default(mPostViewModel2, mId2, true, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$initEvents$1$2.1
                        {
                            super(1);
                        }

                        @Override // kotlin.jvm.functions.Function1
                        public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                            invoke2(obj);
                            return Unit.INSTANCE;
                        }

                        /* renamed from: invoke, reason: avoid collision after fix types in other method */
                        public final void invoke2(@Nullable Object obj) {
                            String valueOf = String.valueOf(obj);
                            HashMap hashMap = new HashMap();
                            if (!(valueOf.length() == 0)) {
                                try {
                                    JSONObject jSONObject = new JSONObject(valueOf);
                                    Iterator<String> keys = jSONObject.keys();
                                    while (keys.hasNext()) {
                                        String key = keys.next();
                                        String value = jSONObject.getString(key);
                                        Intrinsics.checkNotNullExpressionValue(key, "key");
                                        Intrinsics.checkNotNullExpressionValue(value, "value");
                                        hashMap.put(key, value);
                                    }
                                } catch (Exception e2) {
                                    e2.printStackTrace();
                                }
                            }
                            String str = (String) hashMap.get(NotificationCompat.CATEGORY_STATUS);
                            CommentFragment.this.getItv_favorite().setSelected(StringsKt__StringsJVMKt.equals$default(str, "y", false, 2, null));
                            CommentFragment.this.getItv_favorite().setText(StringsKt__StringsJVMKt.equals$default(str, "y", false, 2, null) ? "已收藏" : "收藏");
                        }
                    }, null, 8, null);
                    return;
                }
                PostViewModel mPostViewModel3 = CommentFragment.this.getMPostViewModel();
                mId = CommentFragment.this.getMId();
                final CommentFragment commentFragment2 = CommentFragment.this;
                PostViewModel.novelDoFavorite$default(mPostViewModel3, mId, true, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$initEvents$1$2.2
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                        invoke2(obj);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@Nullable Object obj) {
                        String valueOf = String.valueOf(obj);
                        HashMap hashMap = new HashMap();
                        if (!(valueOf.length() == 0)) {
                            try {
                                JSONObject jSONObject = new JSONObject(valueOf);
                                Iterator<String> keys = jSONObject.keys();
                                while (keys.hasNext()) {
                                    String key = keys.next();
                                    String value = jSONObject.getString(key);
                                    Intrinsics.checkNotNullExpressionValue(key, "key");
                                    Intrinsics.checkNotNullExpressionValue(value, "value");
                                    hashMap.put(key, value);
                                }
                            } catch (Exception e2) {
                                e2.printStackTrace();
                            }
                        }
                        String str = (String) hashMap.get(NotificationCompat.CATEGORY_STATUS);
                        CommentFragment.this.getItv_favorite().setSelected(StringsKt__StringsJVMKt.equals$default(str, "y", false, 2, null));
                        CommentFragment.this.getItv_favorite().setText(StringsKt__StringsJVMKt.equals$default(str, "y", false, 2, null) ? "已收藏" : "收藏");
                    }
                }, null, 8, null);
            }
        }, 1);
        C2354n.m2374A(getItv_confirm_post(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$initEvents$1$3
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageTextView imageTextView) {
                invoke2(imageTextView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageTextView it) {
                String mId;
                String mType;
                Intrinsics.checkNotNullParameter(it, "it");
                String valueOf = String.valueOf(CommentFragment.this.getEd_input_comment().getText());
                if (Intrinsics.areEqual(valueOf, "")) {
                    C2354n.m2449Z("请输入评论内容");
                    return;
                }
                PostViewModel mPostViewModel2 = CommentFragment.this.getMPostViewModel();
                mId = CommentFragment.this.getMId();
                mType = CommentFragment.this.getMType();
                final CommentFragment commentFragment = CommentFragment.this;
                final PostViewModel postViewModel = mPostViewModel;
                mPostViewModel2.commentDo(mId, valueOf, mType, false, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$initEvents$1$3.1
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                        invoke(bool.booleanValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(boolean z) {
                        String mId2;
                        String mType2;
                        if (z) {
                            CommentFragment.this.getEd_input_comment().setText("");
                            PostViewModel postViewModel2 = postViewModel;
                            mId2 = CommentFragment.this.getMId();
                            mType2 = CommentFragment.this.getMType();
                            postViewModel2.commentLogs(mId2, mType2, 1);
                        }
                        CommentFragment.this.hideLoadingDialog();
                    }
                });
            }
        }, 1);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public InterfaceC3053d1 request() {
        InterfaceC3053d1 loadJob = getLoadJob();
        if (loadJob != null) {
            C2354n.m2512s(loadJob, null, 1, null);
        }
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        hashMap.put("id", getMId());
        hashMap.put("type", getMType());
        hashMap.put("page", String.valueOf(getCurrentPage()));
        Unit unit = Unit.INSTANCE;
        setLoadJob(C0917a.m222f(c0917a, "comment/logs", CommentListBean.class, hashMap, new Function1<List<? extends CommentListBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$request$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends CommentListBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends CommentListBean> list) {
                if (list != null) {
                    CommentFragment.this.didRequestComplete(list);
                }
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$request$3
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                C2354n.m2449Z(it.getMessage());
            }
        }, false, false, null, false, 480));
        return getLoadJob();
    }

    public final void sendCommentOut(@NotNull String contentComment) {
        Intrinsics.checkNotNullParameter(contentComment, "contentComment");
        getMPostViewModel().commentDo(getMId(), contentComment, getMType(), false, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$sendCommentOut$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                invoke(bool.booleanValue());
                return Unit.INSTANCE;
            }

            public final void invoke(boolean z) {
                String mId;
                String mType;
                if (z) {
                    CommentFragment.this.getEd_input_comment().setText("");
                    PostViewModel mPostViewModel = CommentFragment.this.getMPostViewModel();
                    mId = CommentFragment.this.getMId();
                    mType = CommentFragment.this.getMType();
                    mPostViewModel.commentLogs(mId, mType, 1);
                }
                CommentFragment.this.hideLoadingDialog();
            }
        });
    }

    public final void setId_comment(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.id_comment = str;
    }

    public final void setType_comment(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.type_comment = str;
    }

    public final void setType_post(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.type_post = str;
    }

    @NotNull
    public final PostViewModel viewModelInstance() {
        return getMPostViewModel();
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull final BaseViewHolder helper, @NotNull final CommentListBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        C2852c m2455a2 = C2354n.m2455a2(requireContext());
        String str = item.img;
        if (str == null) {
            str = "";
        }
        C1558h mo770c = m2455a2.mo770c();
        mo770c.mo763X(str);
        ((C2851b) mo770c).m3292f0().m757R((ImageView) helper.m3912b(R.id.iv_post_comment_userheder));
        TextView textView = (TextView) helper.m3912b(R.id.tv_post_username);
        TextView textView2 = (TextView) helper.m3912b(R.id.tv_post_comment_content);
        TextView textView3 = (TextView) helper.m3912b(R.id.tv_post_comment_time);
        TextView textView4 = (TextView) helper.m3912b(R.id.itv_postcomment_likes);
        TextView textView5 = (TextView) helper.m3912b(R.id.tv_post_comment_reply);
        if (Intrinsics.areEqual(item.user_id, ChatMsgBean.SERVICE_ID)) {
            textView4.setVisibility(8);
            textView5.setVisibility(8);
        } else {
            textView4.setVisibility(0);
            textView5.setVisibility(0);
            C2354n.m2374A(textView5, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$bindItem$1$1
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(TextView textView6) {
                    invoke2(textView6);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull TextView it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                    CommentFragment.this.getTv_input_comment().setFocusable(true);
                    CommentFragment.this.getTv_input_comment().setFocusableInTouchMode(true);
                    CommentFragment.this.getTv_input_comment().requestFocus();
                    Object systemService = CommentFragment.this.getTv_input_comment().getContext().getSystemService("input_method");
                    Objects.requireNonNull(systemService, "null cannot be cast to non-null type android.view.inputmethod.InputMethodManager");
                    ((InputMethodManager) systemService).showSoftInput(CommentFragment.this.getTv_input_comment(), 0);
                    AppCompatEditText tv_input_comment = CommentFragment.this.getTv_input_comment();
                    StringBuilder m586H = C1499a.m586H("回复：");
                    m586H.append((Object) item.nickname);
                    m586H.append(": ");
                    tv_input_comment.setHint(m586H.toString());
                    CommentFragment commentFragment = CommentFragment.this;
                    String str2 = item.f9922id;
                    Intrinsics.checkNotNullExpressionValue(str2, "item.id");
                    commentFragment.setId_comment(str2);
                    CommentFragment.this.setType_post("reply");
                }
            }, 1);
        }
        textView.setText(item.nickname);
        textView2.setText(item.content);
        textView3.setText(item.label);
        textView4.setText(C0843e0.m182a(item.love));
        textView4.setSelected(Intrinsics.areEqual(item.has_love, "y"));
        textView4.setTextColor(Intrinsics.areEqual(item.has_love, "y") ? getResources().getColor(R.color.black) : getResources().getColor(R.color.black));
        C2354n.m2374A(textView4, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$bindItem$1$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView6) {
                invoke2(textView6);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (Intrinsics.areEqual(CommentListBean.this.has_love, "y")) {
                    CommentListBean commentListBean = CommentListBean.this;
                    Intrinsics.checkNotNullExpressionValue(commentListBean.love, "item.love");
                    commentListBean.love = String.valueOf(Integer.parseInt(r0) - 1);
                    CommentListBean.this.has_love = "n";
                } else {
                    CommentListBean commentListBean2 = CommentListBean.this;
                    String str2 = commentListBean2.love;
                    Intrinsics.checkNotNullExpressionValue(str2, "item.love");
                    commentListBean2.love = String.valueOf(Integer.parseInt(str2) + 1);
                    CommentListBean.this.has_love = "y";
                }
                PostViewModel mPostViewModel = this.getMPostViewModel();
                String str3 = CommentListBean.this.f9922id;
                Intrinsics.checkNotNullExpressionValue(str3, "item.id");
                final CommentFragment commentFragment = this;
                mPostViewModel.commentDoLove(str3, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.CommentFragment$bindItem$1$2.1
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                        invoke(bool.booleanValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(boolean z) {
                        CommentFragment.this.hideLoadingDialog();
                    }
                });
                this.getAdapter().notifyItemChanged(helper.getAdapterPosition());
            }
        }, 1);
    }
}
