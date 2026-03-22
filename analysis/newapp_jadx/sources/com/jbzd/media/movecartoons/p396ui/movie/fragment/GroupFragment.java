package com.jbzd.media.movecartoons.p396ui.movie.fragment;

import androidx.recyclerview.widget.RecyclerView;
import com.jbzd.media.movecartoons.p396ui.search.child.CommonLongListFragment;
import com.jbzd.media.movecartoons.view.decoration.ItemDecorationV;
import java.util.HashMap;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0007\u0018\u0000 \u00172\u00020\u0001:\u0001\u0017B\u0007¢\u0006\u0004\b\u0015\u0010\u0016J+\u0010\u0005\u001a\u001e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00030\u0002j\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003`\u0004H\u0016¢\u0006\u0004\b\u0005\u0010\u0006J\u000f\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\b\u0010\tJ\u0011\u0010\u000b\u001a\u0004\u0018\u00010\nH\u0016¢\u0006\u0004\b\u000b\u0010\fJ\u0019\u0010\u000f\u001a\u00020\u000e2\b\u0010\r\u001a\u0004\u0018\u00010\u0003H\u0016¢\u0006\u0004\b\u000f\u0010\u0010J\u000f\u0010\u0012\u001a\u00020\u0011H\u0016¢\u0006\u0004\b\u0012\u0010\u0013J\u000f\u0010\u0014\u001a\u00020\u0011H\u0016¢\u0006\u0004\b\u0014\u0010\u0013¨\u0006\u0018"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/movie/fragment/GroupFragment;", "Lcom/jbzd/media/movecartoons/ui/search/child/CommonLongListFragment;", "Ljava/util/HashMap;", "", "Lkotlin/collections/HashMap;", "getRequestBody", "()Ljava/util/HashMap;", "", "autoRefresh", "()Z", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getItemDecoration", "()Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "group_id", "", "updateGroupId", "(Ljava/lang/String;)V", "", "getLeftPadding", "()I", "getRightPadding", "<init>", "()V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class GroupFragment extends CommonLongListFragment {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\r\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004¨\u0006\u0007"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/movie/fragment/GroupFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/ui/movie/fragment/GroupFragment;", "newInstance", "()Lcom/jbzd/media/movecartoons/ui/movie/fragment/GroupFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final GroupFragment newInstance() {
            return new GroupFragment();
        }
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonLongListFragment, com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonVideoListFragment, com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public boolean autoRefresh() {
        return false;
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonLongListFragment, com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public RecyclerView.ItemDecoration getItemDecoration() {
        return new ItemDecorationV(C2354n.m2425R(requireContext(), 12.0f), C2354n.m2425R(requireContext(), 10.0f));
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonLongListFragment, com.jbzd.media.movecartoons.core.BaseListFragment
    public int getLeftPadding() {
        return 0;
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonLongListFragment, com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonVideoListFragment
    @NotNull
    public HashMap<String, String> getRequestBody() {
        return C1499a.m595Q("canvas", "long");
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonLongListFragment, com.jbzd.media.movecartoons.core.BaseListFragment
    public int getRightPadding() {
        return 0;
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonVideoListFragment
    public void updateGroupId(@Nullable String group_id) {
        if (Intrinsics.areEqual(group_id, getRequestRoomParameter().get("group_id"))) {
            return;
        }
        super.updateGroupId(group_id);
    }
}
