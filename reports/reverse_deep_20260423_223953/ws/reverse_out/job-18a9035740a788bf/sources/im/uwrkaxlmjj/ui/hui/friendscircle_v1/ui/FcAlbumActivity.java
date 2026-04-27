package im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui;

import android.text.TextUtils;
import android.view.View;
import android.widget.AdapterView;
import android.widget.FrameLayout;
import androidx.recyclerview.widget.GridLayoutManager;
import com.bjz.comm.net.bean.RespFcAlbumListBean;
import com.bjz.comm.net.bean.UrlInfoBean;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.mvp.presenter.FCAlbumListPresenter;
import com.scwang.smartrefresh.layout.SmartRefreshLayout;
import com.scwang.smartrefresh.layout.api.RefreshLayout;
import com.scwang.smartrefresh.layout.listener.OnRefreshLoadMoreListener;
import im.uwrkaxlmjj.javaBean.fc.FollowedFcListBean;
import im.uwrkaxlmjj.javaBean.fc.HomeFcListBean;
import im.uwrkaxlmjj.javaBean.fc.RecommendFcListBean;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.decoration.StickyDecoration;
import im.uwrkaxlmjj.ui.decoration.listener.GroupListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FriendsCircleAlbumListAdapter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.helper.FcDBHelper;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AlbumPreviewActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.TimeUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.MyRecyclerView;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.toast.FcToastUtils;
import im.uwrkaxlmjj.ui.hviews.MryEmptyView;
import java.util.ArrayList;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;
import org.json.JSONException;

/* JADX INFO: loaded from: classes5.dex */
public class FcAlbumActivity extends CommFcActivity implements BaseFcContract.IFcPageAlbumListView, AdapterView.OnItemClickListener {
    private MryEmptyView emptyView;
    GridLayoutManager layoutManager;
    private FriendsCircleAlbumListAdapter mAdapter;
    private BaseFcContract.IFcPageAlbumListPresenter mPresenter;
    private MyRecyclerView mRecyclerView;
    private SmartRefreshLayout smartRefreshLayout;
    private String TAG = FcAlbumActivity.class.getSimpleName();
    private long requestId = 0;

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected int getLayoutRes() {
        return R.layout.activity_friends_circle_albums;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected void initView() {
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initActionBar(LocaleController.getString("Gallery", R.string.Gallery));
        this.mRecyclerView = (MyRecyclerView) this.fragmentView.findViewById(R.attr.rv_albums);
        this.smartRefreshLayout = (SmartRefreshLayout) this.fragmentView.findViewById(R.attr.smartRefreshLayout);
        this.mRecyclerView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initEmptyView();
        GridLayoutManager gridLayoutManager = new GridLayoutManager(this.mContext, 3);
        this.layoutManager = gridLayoutManager;
        this.mRecyclerView.setLayoutManager(gridLayoutManager);
        FriendsCircleAlbumListAdapter friendsCircleAlbumListAdapter = new FriendsCircleAlbumListAdapter(new ArrayList(), R.layout.item_friends_circle_album_list, this, getParentActivity());
        this.mAdapter = friendsCircleAlbumListAdapter;
        this.mRecyclerView.setAdapter(friendsCircleAlbumListAdapter);
        StickyDecoration decoration = StickyDecoration.Builder.init(new GroupListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcAlbumActivity.1
            @Override // im.uwrkaxlmjj.ui.decoration.listener.GroupListener
            public String getGroupName(int position) {
                if (FcAlbumActivity.this.mAdapter != null && FcAlbumActivity.this.mAdapter.getDataList().size() > position && position > -1) {
                    return TimeUtils.YearMon(FcAlbumActivity.this.mAdapter.getDataList().get(position).getCreateAt());
                }
                return null;
            }
        }).setGroupBackground(Theme.getColor(Theme.key_windowBackgroundGray)).setGroupHeight(AndroidUtilities.dp(35.0f)).setDivideColor(Theme.getColor(Theme.key_windowBackgroundGray)).setGroupTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText)).setGroupTextSize((int) AndroidUtilities.sp2px(15.0f)).build();
        decoration.resetSpan(this.mRecyclerView, this.layoutManager);
        this.mRecyclerView.addItemDecoration(decoration);
    }

    private void initEmptyView() {
        FrameLayout flContainer = (FrameLayout) this.fragmentView.findViewById(R.attr.fl_container);
        MryEmptyView mryEmptyView = new MryEmptyView(this.mContext);
        this.emptyView = mryEmptyView;
        mryEmptyView.attach(flContainer);
        this.emptyView.setEmptyText(LocaleController.getString(R.string.friendscircle_album_list_no_data));
        this.emptyView.setEmptyResId(R.id.img_empty_default);
        this.emptyView.setErrorResId(R.id.img_empty_default);
        this.emptyView.setOnEmptyClickListener(new MryEmptyView.OnEmptyOrErrorClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcAlbumActivity$kN8dQEblP-K0es2H_xoo5bPv5UA
            @Override // im.uwrkaxlmjj.ui.hviews.MryEmptyView.OnEmptyOrErrorClickListener
            public final boolean onEmptyViewButtonClick(boolean z) {
                return this.f$0.lambda$initEmptyView$0$FcAlbumActivity(z);
            }
        });
        flContainer.addView(this.emptyView, LayoutHelper.createFrame(-1, -1.0f));
    }

    public /* synthetic */ boolean lambda$initEmptyView$0$FcAlbumActivity(boolean isEmptyButton) {
        this.requestId = 0L;
        refreshPageState(true, null);
        getFcAlbumList();
        return false;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected void initData() {
        this.mPresenter = new FCAlbumListPresenter(this);
        this.smartRefreshLayout.setOnRefreshLoadMoreListener(new OnRefreshLoadMoreListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcAlbumActivity.2
            @Override // com.scwang.smartrefresh.layout.listener.OnRefreshListener
            public void onRefresh(RefreshLayout refreshLayout) {
                FcAlbumActivity.this.requestId = 0L;
                FcAlbumActivity.this.getFcAlbumList();
            }

            @Override // com.scwang.smartrefresh.layout.listener.OnLoadMoreListener
            public void onLoadMore(RefreshLayout refreshLayout) {
                List<RespFcAlbumListBean> dataList = FcAlbumActivity.this.mAdapter.getDataList();
                if (dataList != null && dataList.size() > 20) {
                    FcAlbumActivity.this.requestId = dataList.get(dataList.size() - 1).getID();
                    FcAlbumActivity.this.getFcAlbumList();
                }
            }
        });
        this.requestId = 0L;
        refreshPageState(true, null);
        getFcAlbumList();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void refreshPageState(boolean isRefreshing, String errorMsg) {
        if (isRefreshing) {
            this.emptyView.showLoading();
            return;
        }
        if (this.requestId == 0 && !TextUtils.isEmpty(errorMsg) && this.mAdapter.getDataList().size() == 0) {
            this.emptyView.showError(errorMsg);
            return;
        }
        FriendsCircleAlbumListAdapter friendsCircleAlbumListAdapter = this.mAdapter;
        if (friendsCircleAlbumListAdapter != null && friendsCircleAlbumListAdapter.getDataList().size() == 0) {
            this.emptyView.showEmpty();
        } else if (this.emptyView.getCurrentStatus() != 2) {
            this.emptyView.showContent();
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        BaseFcContract.IFcPageAlbumListPresenter iFcPageAlbumListPresenter = this.mPresenter;
        if (iFcPageAlbumListPresenter != null) {
            iFcPageAlbumListPresenter.unSubscribeTask();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void getFcAlbumList() {
        if (this.requestId == 0) {
            this.smartRefreshLayout.setEnableLoadMore(false);
        } else {
            this.smartRefreshLayout.setEnableRefresh(false);
        }
        this.mPresenter.getAlbumList(getUserConfig().getClientUserId(), this.requestId, 20);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageAlbumListView
    public void getAlbumListSucc(ArrayList<RespFcAlbumListBean> data) {
        this.smartRefreshLayout.finishRefresh();
        this.smartRefreshLayout.finishLoadMore();
        setData(data);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageAlbumListView
    public void getAlbumListFailed(String msg) {
        this.smartRefreshLayout.finishRefresh();
        this.smartRefreshLayout.finishLoadMore();
        setData(null);
        FcToastUtils.show(TextUtils.isEmpty(msg) ? Integer.valueOf(R.string.friendscircle_home_request_fail) : msg);
        refreshPageState(false, msg);
    }

    private void setData(ArrayList<RespFcAlbumListBean> data) {
        if (this.requestId == 0) {
            if (data == null || data.size() == 0) {
                this.smartRefreshLayout.setEnableLoadMore(false);
            } else {
                if (data.size() < 20) {
                    this.smartRefreshLayout.setEnableLoadMore(false);
                } else {
                    this.smartRefreshLayout.setEnableLoadMore(true);
                }
                this.mAdapter.refresh(data);
            }
            refreshPageState(false, null);
            return;
        }
        if (data == null || data.size() < 20) {
            this.smartRefreshLayout.setEnableLoadMore(false);
        }
        if (data != null && data.size() > 0) {
            this.mAdapter.loadMore(data);
        }
        refreshPageState(false, null);
    }

    @Override // android.widget.AdapterView.OnItemClickListener
    public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
        List<UrlInfoBean> urlInfoBeanList = new ArrayList<>();
        List<RespFcAlbumListBean> dataList = this.mAdapter.getDataList();
        for (RespFcAlbumListBean bean : dataList) {
            if (bean != null && bean.getName() != null) {
                urlInfoBeanList.add(new UrlInfoBean(bean));
            }
        }
        AlbumPreviewActivity albumPreviewActivity = new AlbumPreviewActivity(urlInfoBeanList, position);
        albumPreviewActivity.setOnDeleteDelegate(new AlbumPreviewActivity.OnDeleteDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcAlbumActivity.3
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AlbumPreviewActivity.OnDeleteDelegate
            public void onDelete(long forumID, int position2) throws JSONException {
                FcDBHelper.getInstance().deleteItemById(RecommendFcListBean.class, forumID);
                FcDBHelper.getInstance().deleteItemById(HomeFcListBean.class, forumID);
                FcDBHelper.getInstance().deleteItemById(FollowedFcListBean.class, forumID);
                NotificationCenter.getInstance(UserConfig.selectedAccount).postNotificationName(NotificationCenter.fcIgnoreOrDeleteItem, FcAlbumActivity.this.TAG, Long.valueOf(forumID));
                FcAlbumActivity.this.mAdapter.removeItemByForumID(forumID);
                FcAlbumActivity.this.refreshPageState(false, null);
            }
        });
        presentFragment(albumPreviewActivity);
    }
}
