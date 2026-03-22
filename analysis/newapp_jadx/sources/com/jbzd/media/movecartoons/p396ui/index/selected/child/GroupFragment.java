package com.jbzd.media.movecartoons.p396ui.index.selected.child;

import com.jbzd.media.movecartoons.p396ui.search.child.CommonShortListFragment;
import com.qnmd.adnnm.da0yzo.R;
import java.util.HashMap;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0002\b\b\u0018\u0000 \u00162\u00020\u0001:\u0001\u0016B\u0007¢\u0006\u0004\b\u0014\u0010\u0015J+\u0010\u0005\u001a\u001e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00030\u0002j\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003`\u0004H\u0016¢\u0006\u0004\b\u0005\u0010\u0006J\u000f\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\u000b\u001a\u00020\nH\u0016¢\u0006\u0004\b\u000b\u0010\fJ!\u0010\u0010\u001a\u00020\u000f2\b\u0010\r\u001a\u0004\u0018\u00010\u00032\b\u0010\u000e\u001a\u0004\u0018\u00010\u0003¢\u0006\u0004\b\u0010\u0010\u0011J\u000f\u0010\u0012\u001a\u00020\nH\u0016¢\u0006\u0004\b\u0012\u0010\fJ\u000f\u0010\u0013\u001a\u00020\nH\u0016¢\u0006\u0004\b\u0013\u0010\f¨\u0006\u0017"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/selected/child/GroupFragment;", "Lcom/jbzd/media/movecartoons/ui/search/child/CommonShortListFragment;", "Ljava/util/HashMap;", "", "Lkotlin/collections/HashMap;", "getRequestBody", "()Ljava/util/HashMap;", "", "autoRefresh", "()Z", "", "getItemLayoutId", "()I", "group_id", "canvas", "", "updateGroupIdAndCanvas", "(Ljava/lang/String;Ljava/lang/String;)V", "getLeftPadding", "getRightPadding", "<init>", "()V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class GroupFragment extends CommonShortListFragment {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\r\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004¨\u0006\u0007"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/selected/child/GroupFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/ui/index/selected/child/GroupFragment;", "newInstance", "()Lcom/jbzd/media/movecartoons/ui/index/selected/child/GroupFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
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

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonShortListFragment, com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonVideoListFragment, com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public boolean autoRefresh() {
        return false;
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonShortListFragment, com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.video_short_item_black;
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonShortListFragment, com.jbzd.media.movecartoons.core.BaseListFragment
    public int getLeftPadding() {
        return 0;
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonShortListFragment, com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonVideoListFragment
    @NotNull
    public HashMap<String, String> getRequestBody() {
        return new HashMap<>();
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonShortListFragment, com.jbzd.media.movecartoons.core.BaseListFragment
    public int getRightPadding() {
        return 0;
    }

    public final void updateGroupIdAndCanvas(@Nullable String group_id, @Nullable String canvas) {
        if (Intrinsics.areEqual(group_id, getRequestRoomParameter().get("group_id")) && Intrinsics.areEqual(canvas, getRequestRoomParameter().get("canvas"))) {
            return;
        }
        HashMap<String, String> requestRoomParameter = getRequestRoomParameter();
        if (canvas == null) {
            canvas = "";
        }
        requestRoomParameter.put("canvas", canvas);
        super.updateGroupId(group_id);
    }
}
