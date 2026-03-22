package com.jbzd.media.movecartoons.p396ui.post;

import android.annotation.SuppressLint;
import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.bean.CommentListBean;
import com.jbzd.media.movecartoons.bean.PostCommentReplyBean;
import com.jbzd.media.movecartoons.bean.event.EventSubscription;
import com.jbzd.media.movecartoons.bean.response.FindBean;
import com.jbzd.media.movecartoons.bean.response.PostDetailBean;
import com.jbzd.media.movecartoons.bean.response.TagSubBean;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import java.util.HashMap;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p146l.C1568e;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p331b.p335f.C2848a;
import p379c.p380a.InterfaceC3053d1;
import p476m.p496b.p497a.C4909c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000v\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0005\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0016\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\bM\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0005\u0010\u0004J\u0015\u0010\b\u001a\u00020\u00022\u0006\u0010\u0007\u001a\u00020\u0006¢\u0006\u0004\b\b\u0010\tJ%\u0010\u000e\u001a\u00020\u00022\u0006\u0010\n\u001a\u00020\u00062\u0006\u0010\u000b\u001a\u00020\u00062\u0006\u0010\r\u001a\u00020\f¢\u0006\u0004\b\u000e\u0010\u000fJm\u0010\u001c\u001a\u00020\u00022\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0011\u001a\u00020\u00102%\b\u0002\u0010\u0017\u001a\u001f\u0012\u0015\u0012\u0013\u0018\u00010\u0013¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(\u0016\u0012\u0004\u0012\u00020\u00020\u00122'\b\u0002\u0010\u001b\u001a!\u0012\u0017\u0012\u00150\u0018j\u0002`\u0019¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(\u001a\u0012\u0004\u0012\u00020\u00020\u0012¢\u0006\u0004\b\u001c\u0010\u001dJm\u0010\u001f\u001a\u00020\u00022\u0006\u0010\u001e\u001a\u00020\u00062\u0006\u0010\u0011\u001a\u00020\u00102%\b\u0002\u0010\u0017\u001a\u001f\u0012\u0015\u0012\u0013\u0018\u00010\u0013¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(\u0016\u0012\u0004\u0012\u00020\u00020\u00122'\b\u0002\u0010\u001b\u001a!\u0012\u0017\u0012\u00150\u0018j\u0002`\u0019¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(\u001a\u0012\u0004\u0012\u00020\u00020\u0012¢\u0006\u0004\b\u001f\u0010\u001dJm\u0010 \u001a\u00020\u00022\u0006\u0010\n\u001a\u00020\u00062\u0006\u0010\u0011\u001a\u00020\u00102%\b\u0002\u0010\u0017\u001a\u001f\u0012\u0015\u0012\u0013\u0018\u00010\u0013¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(\u0016\u0012\u0004\u0012\u00020\u00020\u00122'\b\u0002\u0010\u001b\u001a!\u0012\u0017\u0012\u00150\u0018j\u0002`\u0019¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(\u001a\u0012\u0004\u0012\u00020\u00020\u0012¢\u0006\u0004\b \u0010\u001dJR\u0010#\u001a\u00020\u00022\u0006\u0010\n\u001a\u00020\u00062\u0006\u0010!\u001a\u00020\u00062\u0006\u0010\u000b\u001a\u00020\u00062\b\b\u0002\u0010\u0011\u001a\u00020\u00102!\u0010\u0017\u001a\u001d\u0012\u0013\u0012\u00110\u0010¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(\"\u0012\u0004\u0012\u00020\u00020\u0012¢\u0006\u0004\b#\u0010$J%\u0010&\u001a\u00020\u00022\u0006\u0010%\u001a\u00020\u00062\u0006\u0010!\u001a\u00020\u00062\u0006\u0010\u000b\u001a\u00020\u0006¢\u0006\u0004\b&\u0010'J8\u0010(\u001a\u00020\u00022\u0006\u0010%\u001a\u00020\u00062!\u0010\u0017\u001a\u001d\u0012\u0013\u0012\u00110\u0010¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(\"\u0012\u0004\u0012\u00020\u00020\u0012¢\u0006\u0004\b(\u0010)J8\u0010*\u001a\u00020\u00022\u0006\u0010\n\u001a\u00020\u00062!\u0010\u0017\u001a\u001d\u0012\u0013\u0012\u00110\u0010¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(\"\u0012\u0004\u0012\u00020\u00020\u0012¢\u0006\u0004\b*\u0010)J8\u0010+\u001a\u00020\u00022\u0006\u0010\n\u001a\u00020\u00062!\u0010\u0017\u001a\u001d\u0012\u0013\u0012\u00110\u0010¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(\"\u0012\u0004\u0012\u00020\u00020\u0012¢\u0006\u0004\b+\u0010)JB\u0010,\u001a\u00020\u00022\u0006\u0010\n\u001a\u00020\u00062\b\b\u0002\u0010\u0011\u001a\u00020\u00102!\u0010\u0017\u001a\u001d\u0012\u0013\u0012\u00110\u0010¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(\"\u0012\u0004\u0012\u00020\u00020\u0012¢\u0006\u0004\b,\u0010-J\u0017\u0010/\u001a\u00020\u00022\u0006\u0010.\u001a\u00020\u0006H\u0007¢\u0006\u0004\b/\u0010\tR#\u00105\u001a\b\u0012\u0004\u0012\u00020\u0010008F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b1\u00102\u001a\u0004\b3\u00104R#\u00108\u001a\b\u0012\u0004\u0012\u00020\u0010008F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b6\u00102\u001a\u0004\b7\u00104R)\u0010=\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020:09008F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b;\u00102\u001a\u0004\b<\u00104R#\u0010A\u001a\b\u0012\u0004\u0012\u00020>008F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b?\u00102\u001a\u0004\b@\u00104R#\u0010E\u001a\b\u0012\u0004\u0012\u00020B008F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bC\u00102\u001a\u0004\bD\u00104R\u0018\u0010G\u001a\u0004\u0018\u00010F8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bG\u0010HR)\u0010L\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020I09008F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bJ\u00102\u001a\u0004\bK\u00104¨\u0006N"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/PostViewModel;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "onCreate", "()V", "onDestroy", "", "postId", "postDetail", "(Ljava/lang/String;)V", "id", "type", "", "page", "commentLogs", "(Ljava/lang/String;Ljava/lang/String;I)V", "", "hasLoading", "Lkotlin/Function1;", "", "Lkotlin/ParameterName;", "name", "response", FindBean.status_success, "Ljava/lang/Exception;", "Lkotlin/Exception;", C1568e.f1949a, "error", "postDoFavorite", "(Ljava/lang/String;ZLkotlin/jvm/functions/Function1;Lkotlin/jvm/functions/Function1;)V", "comicsId", "comicsDoFavorite", "novelDoFavorite", "content", "bool", "commentDo", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLkotlin/jvm/functions/Function1;)V", "commentId", "commentDoReply", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", "commentDoLove", "(Ljava/lang/String;Lkotlin/jvm/functions/Function1;)V", "userDoFollow", "postDoLove", "postDoBuy", "(Ljava/lang/String;ZLkotlin/jvm/functions/Function1;)V", "position", "postCategories", "Landroidx/lifecycle/MutableLiveData;", "historyUpdateSuccess$delegate", "Lkotlin/Lazy;", "getHistoryUpdateSuccess", "()Landroidx/lifecycle/MutableLiveData;", "historyUpdateSuccess", "buyPostSuccess$delegate", "getBuyPostSuccess", "buyPostSuccess", "", "Lcom/jbzd/media/movecartoons/bean/response/TagSubBean;", "tagSubBean$delegate", "getTagSubBean", "tagSubBean", "Lcom/jbzd/media/movecartoons/bean/response/PostDetailBean;", "postDetailBean$delegate", "getPostDetailBean", "postDetailBean", "Lcom/jbzd/media/movecartoons/bean/PostCommentReplyBean;", "mPostCommentReplyBean$delegate", "getMPostCommentReplyBean", "mPostCommentReplyBean", "Lc/a/d1;", "timeCountDownJob", "Lc/a/d1;", "Lcom/jbzd/media/movecartoons/bean/CommentListBean;", "mCommentListBean$delegate", "getMCommentListBean", "mCommentListBean", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostViewModel extends BaseViewModel {

    @Nullable
    private InterfaceC3053d1 timeCountDownJob;

    /* renamed from: postDetailBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy postDetailBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<PostDetailBean>>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$postDetailBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<PostDetailBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: mCommentListBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mCommentListBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<List<? extends CommentListBean>>>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$mCommentListBean$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<List<? extends CommentListBean>> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: mPostCommentReplyBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mPostCommentReplyBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<PostCommentReplyBean>>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$mPostCommentReplyBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<PostCommentReplyBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: buyPostSuccess$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy buyPostSuccess = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$buyPostSuccess$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: historyUpdateSuccess$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy historyUpdateSuccess = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$historyUpdateSuccess$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: tagSubBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tagSubBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<List<? extends TagSubBean>>>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$tagSubBean$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<List<? extends TagSubBean>> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void comicsDoFavorite$default(PostViewModel postViewModel, String str, boolean z, Function1 function1, Function1 function12, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            function1 = new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$comicsDoFavorite$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Object obj2) {
                    invoke2(obj2);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable Object obj2) {
                }
            };
        }
        if ((i2 & 8) != 0) {
            function12 = new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$comicsDoFavorite$2
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                    invoke2(exc);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull Exception it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            };
        }
        postViewModel.comicsDoFavorite(str, z, function1, function12);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void novelDoFavorite$default(PostViewModel postViewModel, String str, boolean z, Function1 function1, Function1 function12, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            function1 = new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$novelDoFavorite$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Object obj2) {
                    invoke2(obj2);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable Object obj2) {
                }
            };
        }
        if ((i2 & 8) != 0) {
            function12 = new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$novelDoFavorite$2
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                    invoke2(exc);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull Exception it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            };
        }
        postViewModel.novelDoFavorite(str, z, function1, function12);
    }

    public static /* synthetic */ void postDoBuy$default(PostViewModel postViewModel, String str, boolean z, Function1 function1, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        postViewModel.postDoBuy(str, z, function1);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void postDoFavorite$default(PostViewModel postViewModel, String str, boolean z, Function1 function1, Function1 function12, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            function1 = new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$postDoFavorite$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Object obj2) {
                    invoke2(obj2);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable Object obj2) {
                }
            };
        }
        if ((i2 & 8) != 0) {
            function12 = new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$postDoFavorite$2
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                    invoke2(exc);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull Exception it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            };
        }
        postViewModel.postDoFavorite(str, z, function1, function12);
    }

    public final void comicsDoFavorite(@NotNull String comicsId, boolean hasLoading, @NotNull Function1<Object, Unit> success, @NotNull Function1<? super Exception, Unit> error) {
        Intrinsics.checkNotNullParameter(comicsId, "comicsId");
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap hashMap = new HashMap();
        hashMap.put("id", comicsId);
        C0917a.m221e(C0917a.f372a, "comics/doFavorite", String.class, hashMap, success, error, false, false, null, false, 480);
    }

    public final void commentDo(@NotNull String id, @NotNull String content, @NotNull String type, boolean hasLoading, @NotNull final Function1<? super Boolean, Unit> success) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(content, "content");
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(success, "success");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap m596R = C1499a.m596R("id", id, "content", content);
        m596R.put("type", type);
        C0917a.m221e(C0917a.f372a, "comment/do", String.class, m596R, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$commentDo$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                C2354n.m2409L1("评论成功");
                success.invoke(Boolean.TRUE);
                this.getLoading().setValue(new C2848a(false, null, false, false, 14));
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$commentDo$3
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
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
                C2354n.m2449Z("评论失败");
                success.invoke(Boolean.FALSE);
                this.getLoading().setValue(new C2848a(false, null, false, false, 14));
            }
        }, false, false, null, false, 480);
    }

    public final void commentDoLove(@NotNull String commentId, @NotNull final Function1<? super Boolean, Unit> success) {
        Intrinsics.checkNotNullParameter(commentId, "commentId");
        Intrinsics.checkNotNullParameter(success, "success");
        getLoading().setValue(new C2848a(true, null, false, false, 14));
        C0917a c0917a = C0917a.f372a;
        HashMap m595Q = C1499a.m595Q("id", commentId);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "comment/doLove", String.class, m595Q, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$commentDoLove$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                PostViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                success.invoke(Boolean.TRUE);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$commentDoLove$3
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
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
                success.invoke(Boolean.FALSE);
                this.getLoading().setValue(new C2848a(false, null, false, false, 14));
            }
        }, false, false, null, false, 480);
    }

    public final void commentDoReply(@NotNull String commentId, @NotNull String content, @NotNull String type) {
        Intrinsics.checkNotNullParameter(commentId, "commentId");
        Intrinsics.checkNotNullParameter(content, "content");
        Intrinsics.checkNotNullParameter(type, "type");
        getLoading().setValue(new C2848a(true, null, false, false, 14));
        C0917a c0917a = C0917a.f372a;
        HashMap m596R = C1499a.m596R("id", "e755939ebf5fb088", "content", content);
        m596R.put("type", "reply");
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "comment/doReply", PostCommentReplyBean.class, m596R, new Function1<PostCommentReplyBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$commentDoReply$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(PostCommentReplyBean postCommentReplyBean) {
                invoke2(postCommentReplyBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable PostCommentReplyBean postCommentReplyBean) {
                PostViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                PostViewModel.this.getMPostCommentReplyBean().setValue(postCommentReplyBean);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$commentDoReply$3
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
                C2354n.m2449Z(it.getMessage());
                PostViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
            }
        }, false, false, null, false, 480);
    }

    public final void commentLogs(@NotNull String id, @NotNull String type, int page) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(type, "type");
        getLoading().setValue(new C2848a(true, null, false, false, 14));
        C0917a c0917a = C0917a.f372a;
        HashMap m596R = C1499a.m596R("id", id, "type", type);
        m596R.put("page", String.valueOf(page));
        m596R.put("page_size", "10");
        Unit unit = Unit.INSTANCE;
        C0917a.m222f(c0917a, "comment/logs", CommentListBean.class, m596R, new Function1<List<? extends CommentListBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$commentLogs$2
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
                PostViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                PostViewModel.this.getMCommentListBean().setValue(list);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$commentLogs$3
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
                C2354n.m2449Z(it.getMessage());
                PostViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
            }
        }, false, false, null, false, 480);
    }

    @NotNull
    public final MutableLiveData<Boolean> getBuyPostSuccess() {
        return (MutableLiveData) this.buyPostSuccess.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getHistoryUpdateSuccess() {
        return (MutableLiveData) this.historyUpdateSuccess.getValue();
    }

    @NotNull
    public final MutableLiveData<List<CommentListBean>> getMCommentListBean() {
        return (MutableLiveData) this.mCommentListBean.getValue();
    }

    @NotNull
    public final MutableLiveData<PostCommentReplyBean> getMPostCommentReplyBean() {
        return (MutableLiveData) this.mPostCommentReplyBean.getValue();
    }

    @NotNull
    public final MutableLiveData<PostDetailBean> getPostDetailBean() {
        return (MutableLiveData) this.postDetailBean.getValue();
    }

    @NotNull
    public final MutableLiveData<List<TagSubBean>> getTagSubBean() {
        return (MutableLiveData) this.tagSubBean.getValue();
    }

    public final void novelDoFavorite(@NotNull String id, boolean hasLoading, @NotNull Function1<Object, Unit> success, @NotNull Function1<? super Exception, Unit> error) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap hashMap = new HashMap();
        hashMap.put("id", id);
        C0917a.m221e(C0917a.f372a, "novel/doFavorite", String.class, hashMap, success, error, false, false, null, false, 480);
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onCreate() {
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onDestroy() {
        super.onDestroy();
        cancelJob(this.timeCountDownJob);
    }

    @SuppressLint({"SuspiciousIndentation"})
    public final void postCategories(@NotNull String position) {
        Intrinsics.checkNotNullParameter(position, "position");
        getLoading().setValue(new C2848a(true, null, false, false, 14));
        HashMap hashMap = new HashMap();
        hashMap.put("position", position);
        C0917a.m222f(C0917a.f372a, "post/categories", TagSubBean.class, hashMap, new Function1<List<? extends TagSubBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$postCategories$2
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
                PostViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                PostViewModel.this.getTagSubBean().setValue(list);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$postCategories$3
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
                PostViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                C2354n.m2449Z(it.getMessage());
            }
        }, false, false, null, false, 480);
    }

    public final void postDetail(@NotNull String postId) {
        Intrinsics.checkNotNullParameter(postId, "postId");
        getLoading().setValue(new C2848a(true, null, false, false, 14));
        C0917a c0917a = C0917a.f372a;
        HashMap m595Q = C1499a.m595Q("id", postId);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "post/detail", PostDetailBean.class, m595Q, new Function1<PostDetailBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$postDetail$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(PostDetailBean postDetailBean) {
                invoke2(postDetailBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable PostDetailBean postDetailBean) {
                PostViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                PostViewModel.this.getPostDetailBean().setValue(postDetailBean);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$postDetail$3
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
                C2354n.m2449Z(it.getMessage());
                PostViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
            }
        }, false, false, null, false, 480);
    }

    public final void postDoBuy(@NotNull String id, final boolean hasLoading, @NotNull final Function1<? super Boolean, Unit> success) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(success, "success");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        C0917a.m221e(C0917a.f372a, "post/doBuy", String.class, C1499a.m595Q("id", id), new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$postDoBuy$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                Function1<Boolean, Unit> function1 = success;
                Boolean bool = Boolean.TRUE;
                function1.invoke(bool);
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                this.getBuyPostSuccess().setValue(bool);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$postDoBuy$3
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
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
                success.invoke(Boolean.FALSE);
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            }
        }, false, false, null, false, 480);
    }

    public final void postDoFavorite(@NotNull String postId, boolean hasLoading, @NotNull Function1<Object, Unit> success, @NotNull Function1<? super Exception, Unit> error) {
        Intrinsics.checkNotNullParameter(postId, "postId");
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap hashMap = new HashMap();
        hashMap.put("id", postId);
        C0917a.m221e(C0917a.f372a, "post/doFavorite", String.class, hashMap, success, error, false, false, null, false, 480);
    }

    public final void postDoLove(@NotNull String id, @NotNull final Function1<? super Boolean, Unit> success) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(success, "success");
        HashMap hashMap = new HashMap();
        hashMap.put("id", id);
        C0917a.m221e(C0917a.f372a, "post/doLove", String.class, hashMap, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$postDoLove$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                success.invoke(Boolean.TRUE);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$postDoLove$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
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
                success.invoke(Boolean.FALSE);
            }
        }, false, false, null, false, 480);
    }

    public final void userDoFollow(@NotNull String id, @NotNull final Function1<? super Boolean, Unit> success) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(success, "success");
        HashMap hashMap = new HashMap();
        hashMap.put("id", id);
        C0917a.m221e(C0917a.f372a, "user/doFollow", String.class, hashMap, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$userDoFollow$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                success.invoke(Boolean.TRUE);
                C4909c.m5569b().m5574g(new EventSubscription());
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostViewModel$userDoFollow$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
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
                success.invoke(Boolean.FALSE);
            }
        }, false, false, null, false, 480);
    }
}
