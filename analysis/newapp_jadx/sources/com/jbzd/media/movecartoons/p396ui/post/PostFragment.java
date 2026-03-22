package com.jbzd.media.movecartoons.p396ui.post;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.core.app.NotificationCompat;
import androidx.recyclerview.widget.RecyclerView;
import com.drake.brv.BindingAdapter;
import com.google.android.flexbox.FlexboxLayoutManager;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.event.EventSubscription;
import com.jbzd.media.movecartoons.bean.response.PostDetailBean;
import com.jbzd.media.movecartoons.bean.response.PostListBean;
import com.jbzd.media.movecartoons.bean.response.VideoTypeBean;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import com.jbzd.media.movecartoons.p396ui.BaseListFragment;
import com.jbzd.media.movecartoons.p396ui.post.topic.PostDetailActivity;
import com.jbzd.media.movecartoons.view.FollowTextView;
import com.jbzd.media.movecartoons.view.PostFileView;
import com.qnmd.adnnm.da0yzo.R;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Ref;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.json.JSONObject;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p403d.p404a.p405a.p407b.p408a.C4195m;
import p476m.p496b.p497a.C4909c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000>\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0006\b&\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u0001B\u0007¢\u0006\u0004\b\u0019\u0010\u001aJ/\u0010\u000b\u001a\u00020\n2\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0006\u001a\u00020\u00052\u0006\u0010\b\u001a\u00020\u00072\u0006\u0010\t\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u000b\u0010\fJ\u001f\u0010\u0011\u001a\u00020\n2\u0006\u0010\u000e\u001a\u00020\r2\u0006\u0010\u0010\u001a\u00020\u000fH\u0016¢\u0006\u0004\b\u0011\u0010\u0012J\u0017\u0010\u0013\u001a\u00020\n2\u0006\u0010\u000e\u001a\u00020\rH\u0016¢\u0006\u0004\b\u0013\u0010\u0014J#\u0010\u0017\u001a\u00020\n2\n\u0010\u0016\u001a\u00060\u0015R\u00020\r2\u0006\u0010\t\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0017\u0010\u0018¨\u0006\u001b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/PostFragment;", "Lcom/jbzd/media/movecartoons/ui/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/PostListBean;", "Landroid/view/View;", "fileView", "", "showVip", "Lcom/jbzd/media/movecartoons/bean/response/PostDetailBean$FilesBean;", "file", "data", "", "bindFileToView", "(Landroid/view/View;ZLcom/jbzd/media/movecartoons/bean/response/PostDetailBean$FilesBean;Lcom/jbzd/media/movecartoons/bean/response/PostListBean;)V", "Lcom/drake/brv/BindingAdapter;", "adapter", "Landroidx/recyclerview/widget/RecyclerView;", "rv", "addItemListType", "(Lcom/drake/brv/BindingAdapter;Landroidx/recyclerview/widget/RecyclerView;)V", "onViewClick", "(Lcom/drake/brv/BindingAdapter;)V", "Lcom/drake/brv/BindingAdapter$BindingViewHolder;", "vh", "onDataBinding", "(Lcom/drake/brv/BindingAdapter$BindingViewHolder;Lcom/jbzd/media/movecartoons/bean/response/PostListBean;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class PostFragment extends BaseListFragment<PostListBean> {
    private final void bindFileToView(View fileView, boolean showVip, PostDetailBean.FilesBean file, PostListBean data) {
        ImageView imageView = (ImageView) fileView.findViewById(R.id.img_community_single);
        TextView vipView = (TextView) fileView.findViewById(R.id.txt_post_vip);
        ImageView moneyView = (ImageView) fileView.findViewById(R.id.img_icon_money);
        ImageView imagePause = (ImageView) fileView.findViewById(R.id.iv_pause);
        C2354n.m2459b2(imageView).m3298p(file.image).m3295i0().m757R(imageView);
        Intrinsics.checkNotNullExpressionValue(vipView, "vipView");
        vipView.setVisibility(!Intrinsics.areEqual(data.pay_type, VideoTypeBean.video_type_free) && !Intrinsics.areEqual(data.pay_type, "money") && showVip ? 0 : 8);
        Intrinsics.checkNotNullExpressionValue(moneyView, "moneyView");
        moneyView.setVisibility(Intrinsics.areEqual(data.pay_type, "money") ? 0 : 8);
        Intrinsics.checkNotNullExpressionValue(imagePause, "imagePause");
        imagePause.setVisibility(Intrinsics.areEqual(file.type, "image") ^ true ? 0 : 8);
    }

    @Override // com.jbzd.media.movecartoons.p396ui.BaseListFragment, com.qunidayede.supportlibrary.core.view.BaseBindingFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.p396ui.BaseListFragment
    public void addItemListType(@NotNull BindingAdapter adapter, @NotNull RecyclerView rv) {
        boolean m616f0 = C1499a.m616f0(adapter, "adapter", rv, "rv", PostListBean.class);
        final int i2 = R.layout.item_post_layout;
        if (m616f0) {
            adapter.f8910l.put(Reflection.typeOf(PostListBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.post.PostFragment$addItemListType$$inlined$addType$1
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(2);
                }

                @NotNull
                public final Integer invoke(@NotNull Object obj, int i3) {
                    Intrinsics.checkNotNullParameter(obj, "$this$null");
                    return Integer.valueOf(i2);
                }

                @Override // kotlin.jvm.functions.Function2
                public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                    return invoke(obj, num.intValue());
                }
            });
        } else {
            adapter.f8909k.put(Reflection.typeOf(PostListBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.post.PostFragment$addItemListType$$inlined$addType$2
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(2);
                }

                @NotNull
                public final Integer invoke(@NotNull Object obj, int i3) {
                    Intrinsics.checkNotNullParameter(obj, "$this$null");
                    return Integer.valueOf(i2);
                }

                @Override // kotlin.jvm.functions.Function2
                public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                    return invoke(obj, num.intValue());
                }
            });
        }
    }

    @Override // com.jbzd.media.movecartoons.p396ui.BaseListFragment
    public void onViewClick(@NotNull BindingAdapter adapter) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        adapter.m3937n(new int[]{R.id.root}, new Function2<BindingAdapter.BindingViewHolder, Integer, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostFragment$onViewClick$1
            {
                super(2);
            }

            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder, Integer num) {
                invoke(bindingViewHolder, num.intValue());
                return Unit.INSTANCE;
            }

            public final void invoke(@NotNull BindingAdapter.BindingViewHolder onClick, int i2) {
                Intrinsics.checkNotNullParameter(onClick, "$this$onClick");
                PostDetailActivity.Companion companion = PostDetailActivity.Companion;
                Context requireContext = PostFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                String str = ((PostListBean) onClick.m3942b()).f9980id;
                Intrinsics.checkNotNullExpressionValue(str, "getModel<PostListBean>().id");
                companion.start(requireContext, str);
            }
        });
    }

    @Override // com.jbzd.media.movecartoons.p396ui.BaseListFragment
    public void onDataBinding(@NotNull BindingAdapter.BindingViewHolder vh, @NotNull final PostListBean data) {
        ViewGroup viewGroup;
        Intrinsics.checkNotNullParameter(vh, "vh");
        Intrinsics.checkNotNullParameter(data, "data");
        FollowTextView followTextView = (FollowTextView) vh.m3941a(R.id.itv_postuser_follow);
        String str = data.user.f9982id;
        MyApp myApp = MyApp.f9891f;
        followTextView.setVisibility(Intrinsics.areEqual(str, MyApp.f9892g.user_id) ? 4 : 0);
        followTextView.setFollowStatus(data.user.isFollow());
        C2354n.m2374A(followTextView, 0L, new Function1<FollowTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostFragment$onDataBinding$1$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(FollowTextView followTextView2) {
                invoke2(followTextView2);
                return Unit.INSTANCE;
            }

            /* JADX WARN: Type inference failed for: r2v3, types: [T, java.lang.String] */
            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull FollowTextView it) {
                List<Object> list;
                Intrinsics.checkNotNullParameter(it, "it");
                final Ref.ObjectRef objectRef = new Ref.ObjectRef();
                objectRef.element = PostListBean.this.user.f9982id;
                BindingAdapter adapter = this.getAdapter();
                if (adapter != null && (list = adapter.f8920v) != null) {
                    for (Object obj : list) {
                        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.PostListBean");
                        PostListBean postListBean = (PostListBean) obj;
                        if (Intrinsics.areEqual(postListBean.user.f9982id, objectRef.element)) {
                            if (Intrinsics.areEqual(postListBean.user.is_follow, "n")) {
                                postListBean.user.is_follow = "y";
                            } else {
                                postListBean.user.is_follow = "n";
                            }
                        }
                    }
                }
                HashMap hashMap = new HashMap();
                T userId = objectRef.element;
                Intrinsics.checkNotNullExpressionValue(userId, "userId");
                hashMap.put("id", userId);
                C0917a c0917a = C0917a.f372a;
                final PostFragment postFragment = this;
                C0917a.m221e(c0917a, "user/doFollow", String.class, hashMap, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostFragment$onDataBinding$1$1.2
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(String str2) {
                        invoke2(str2);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@Nullable String str2) {
                        BindingAdapter adapter2 = PostFragment.this.getAdapter();
                        if (adapter2 != null) {
                            adapter2.notifyDataSetChanged();
                        }
                        C4909c m5569b = C4909c.m5569b();
                        String str3 = objectRef.element;
                        String valueOf = String.valueOf(str2);
                        HashMap hashMap2 = new HashMap();
                        if (!(valueOf.length() == 0)) {
                            try {
                                JSONObject jSONObject = new JSONObject(valueOf);
                                Iterator<String> keys = jSONObject.keys();
                                while (keys.hasNext()) {
                                    String key = keys.next();
                                    String value = jSONObject.getString(key);
                                    Intrinsics.checkNotNullExpressionValue(key, "key");
                                    Intrinsics.checkNotNullExpressionValue(value, "value");
                                    hashMap2.put(key, value);
                                }
                            } catch (Exception e2) {
                                e2.printStackTrace();
                            }
                        }
                        m5569b.m5574g(new EventSubscription(str3, (String) hashMap2.get(NotificationCompat.CATEGORY_STATUS)));
                    }
                }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostFragment$onDataBinding$1$1.3
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                        invoke2(exc);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull Exception it2) {
                        Intrinsics.checkNotNullParameter(it2, "it");
                    }
                }, false, false, null, false, 480);
            }
        }, 1);
        ((TextView) vh.m3941a(R.id.txt_praise)).setSelected(Intrinsics.areEqual(data.has_love, "y"));
        RecyclerView recyclerView = (RecyclerView) vh.m3941a(R.id.rv_tag_post);
        FlexboxLayoutManager flexboxLayoutManager = new FlexboxLayoutManager(recyclerView.getContext());
        flexboxLayoutManager.m4176y(1);
        flexboxLayoutManager.m4175x(0);
        Unit unit = Unit.INSTANCE;
        recyclerView.setLayoutManager(flexboxLayoutManager);
        C4195m.m4774J0(recyclerView, new Function2<BindingAdapter, RecyclerView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostFragment$onDataBinding$3$2
            {
                super(2);
            }

            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter bindingAdapter, RecyclerView recyclerView2) {
                invoke2(bindingAdapter, recyclerView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull BindingAdapter bindingAdapter, @NotNull RecyclerView recyclerView2) {
                boolean m616f0 = C1499a.m616f0(bindingAdapter, "$this$setup", recyclerView2, "it", TagBean.class);
                final int i2 = R.layout.item_tag_move_detail;
                if (m616f0) {
                    bindingAdapter.f8910l.put(Reflection.typeOf(TagBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.post.PostFragment$onDataBinding$3$2$invoke$$inlined$addType$1
                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                        {
                            super(2);
                        }

                        @NotNull
                        public final Integer invoke(@NotNull Object obj, int i3) {
                            Intrinsics.checkNotNullParameter(obj, "$this$null");
                            return Integer.valueOf(i2);
                        }

                        @Override // kotlin.jvm.functions.Function2
                        public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                            return invoke(obj, num.intValue());
                        }
                    });
                } else {
                    bindingAdapter.f8909k.put(Reflection.typeOf(TagBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.post.PostFragment$onDataBinding$3$2$invoke$$inlined$addType$2
                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                        {
                            super(2);
                        }

                        @NotNull
                        public final Integer invoke(@NotNull Object obj, int i3) {
                            Intrinsics.checkNotNullParameter(obj, "$this$null");
                            return Integer.valueOf(i2);
                        }

                        @Override // kotlin.jvm.functions.Function2
                        public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                            return invoke(obj, num.intValue());
                        }
                    });
                }
                bindingAdapter.m3935l(new Function1<BindingAdapter.BindingViewHolder, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostFragment$onDataBinding$3$2.1
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder) {
                        invoke2(bindingViewHolder);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull BindingAdapter.BindingViewHolder onBind) {
                        Intrinsics.checkNotNullParameter(onBind, "$this$onBind");
                        ((TextView) onBind.m3941a(R.id.tv_content)).setText(((TagBean) onBind.m3942b()).name);
                    }
                });
                C38522 listener = new Function2<BindingAdapter.BindingViewHolder, Integer, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.PostFragment$onDataBinding$3$2.2
                    @Override // kotlin.jvm.functions.Function2
                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder, Integer num) {
                        invoke(bindingViewHolder, num.intValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(@NotNull BindingAdapter.BindingViewHolder onClick, int i3) {
                        Intrinsics.checkNotNullParameter(onClick, "$this$onClick");
                    }
                };
                Intrinsics.checkNotNullParameter(listener, "listener");
                bindingAdapter.f8911m.put(Integer.valueOf(R.id.tv_content), new Pair<>(listener, Boolean.FALSE));
                bindingAdapter.m3939q(PostListBean.this.categories);
            }
        });
        PostFileView postFileView = (PostFileView) vh.m3941a(R.id.layout_post_file);
        postFileView.removeAllViews();
        List<PostDetailBean.FilesBean> list = data.files;
        if (list == null || list.isEmpty()) {
            postFileView.setVisibility(8);
            return;
        }
        postFileView.setVisibility(0);
        int size = data.files.size();
        View m4803e0 = C4195m.m4803e0(postFileView, R.layout.layout_post_file);
        PostDetailBean.FilesBean filesBean = data.files.get(0);
        Intrinsics.checkNotNullExpressionValue(filesBean, "data.files[0]");
        bindFileToView(m4803e0, true, filesBean, data);
        postFileView.addView(m4803e0);
        if (size >= 2) {
            viewGroup = (ViewGroup) C4195m.m4803e0(postFileView, R.layout.layout_post_file);
            PostDetailBean.FilesBean filesBean2 = data.files.get(1);
            Intrinsics.checkNotNullExpressionValue(filesBean2, "data.files[1]");
            bindFileToView(viewGroup, false, filesBean2, data);
            postFileView.addView(viewGroup);
        } else {
            viewGroup = null;
        }
        if (size >= 3) {
            View m4803e02 = C4195m.m4803e0(postFileView, R.layout.layout_post_file);
            PostDetailBean.FilesBean file = data.files.get(2);
            Intrinsics.checkNotNullExpressionValue(file, "file");
            bindFileToView(m4803e02, false, file, data);
            TextView countText = (TextView) m4803e02.findViewById(R.id.txt_count);
            if (size <= 3) {
                Intrinsics.checkNotNullExpressionValue(countText, "countText");
                countText.setVisibility(8);
            } else if (Intrinsics.areEqual(file.type, "image")) {
                Intrinsics.checkNotNullExpressionValue(countText, "countText");
                countText.setVisibility(0);
                countText.setText(getString(R.string.add_holder, Integer.valueOf(size - 3)));
            } else {
                TextView textView = viewGroup != null ? (TextView) viewGroup.findViewById(R.id.txt_count) : null;
                if (textView != null) {
                    textView.setVisibility(0);
                }
                if (textView != null) {
                    textView.setText(getString(R.string.add_holder, Integer.valueOf(size - 3)));
                }
                Intrinsics.checkNotNullExpressionValue(countText, "countText");
                countText.setVisibility(8);
            }
            postFileView.addView(m4803e02);
        }
    }
}
