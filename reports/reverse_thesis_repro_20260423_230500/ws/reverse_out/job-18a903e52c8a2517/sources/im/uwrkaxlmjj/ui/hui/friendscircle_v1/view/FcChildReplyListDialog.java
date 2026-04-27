package im.uwrkaxlmjj.ui.hui.friendscircle_v1.view;

import android.app.Activity;
import android.content.Context;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.bjz.comm.net.bean.FcLikeBean;
import com.bjz.comm.net.bean.FcReplyBean;
import com.bjz.comm.net.bean.FcUserInfoBean;
import com.blankj.utilcode.util.ScreenUtils;
import com.scwang.smartrefresh.layout.SmartRefreshLayout;
import com.scwang.smartrefresh.layout.api.RefreshLayout;
import com.scwang.smartrefresh.layout.listener.OnRefreshLoadMoreListener;
import com.socks.library.KLog;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.utils.ShapeUtils;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.adapter.FcDialogChildReplyAdapter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.StringUtils;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.util.ArrayList;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FcChildReplyListDialog extends BottomSheet {
    private int currentUserId;
    private LinearLayoutManager layoutManager;
    private ChildReplyListListener listener;
    private SmartRefreshLayout mChildRefreshLayout;
    private FcDialogChildReplyAdapter mChildReplyListAdapter;
    private RecyclerView rvReplyList;
    private int scrollOffsetY;

    public interface ChildReplyListListener {
        void onChildReplyClick(View view, String str, FcReplyBean fcReplyBean, int i, int i2, boolean z);

        void onChildReplyListAction(View view, int i, int i2, Object obj);

        void onPresentFragment(BaseFragment baseFragment);

        void onReplyLoadMoreData(FcReplyBean fcReplyBean, int i);

        void onReplyRefreshData();
    }

    public FcChildReplyListDialog(Activity context) {
        this(context, false, 1);
        this.currentUserId = AccountInstance.getInstance(UserConfig.selectedAccount).getUserConfig().getCurrentUser().id;
    }

    public FcChildReplyListDialog(Context context, boolean needFocus, int backgroundType) {
        super(context, needFocus, backgroundType);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected void init(Context context, boolean needFocus, int backgroundType) {
        super.init(context, needFocus, backgroundType);
        setApplyBottomPadding(false);
        View view = LayoutInflater.from(context).inflate(R.layout.dialog_fc_reply_list, (ViewGroup) null);
        setApplyBottomPadding(false);
        setApplyTopPadding(false);
        initView(view);
    }

    private void initView(View view) {
        final int calHeight = ScreenUtils.getScreenHeight() - AndroidUtilities.dp(25.0f);
        this.containerView = new FrameLayout(getContext()) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcChildReplyListDialog.1
            @Override // android.widget.FrameLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                int height = View.MeasureSpec.getSize(heightMeasureSpec);
                if (height >= calHeight) {
                    height = calHeight;
                }
                super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(height, 1073741824));
            }

            @Override // android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent ev) {
                if (ev.getAction() == 0 && FcChildReplyListDialog.this.scrollOffsetY != 0 && ev.getY() < FcChildReplyListDialog.this.scrollOffsetY - AndroidUtilities.dp(30.0f)) {
                    FcChildReplyListDialog.this.dismiss();
                    return true;
                }
                return super.onInterceptTouchEvent(ev);
            }

            @Override // android.view.View
            public boolean onTouchEvent(MotionEvent e) {
                return !FcChildReplyListDialog.this.isDismissed() && super.onTouchEvent(e);
            }
        };
        this.containerView.setBackground(this.shadowDrawable);
        view.findViewById(R.attr.fl_content).setBackground(ShapeUtils.createTop(Theme.getColor(Theme.key_windowBackgroundWhite), AndroidUtilities.dp(15.0f), AndroidUtilities.dp(15.0f)));
        view.findViewById(R.attr.view_divider).setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        view.findViewById(R.attr.iv_close).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcChildReplyListDialog.2
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                FcChildReplyListDialog.this.dismiss();
            }
        });
        view.findViewById(R.attr.btn_reply).setBackground(ShapeUtils.createStrokeAndFill(view.getResources().getColor(R.color.color_FFD8D8D8), AndroidUtilities.dp(1.0f), AndroidUtilities.dp(20.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        view.findViewById(R.attr.btn_reply).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcChildReplyListDialog.3
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                FcReplyBean parentFcReplyBean;
                if (FcChildReplyListDialog.this.listener != null && FcChildReplyListDialog.this.mChildReplyListAdapter != null && (parentFcReplyBean = FcChildReplyListDialog.this.mChildReplyListAdapter.getParentFcReplyBean()) != null && FcChildReplyListDialog.this.currentUserId != parentFcReplyBean.getCreateBy() && parentFcReplyBean.getCreator() != null) {
                    FcUserInfoBean fcUserInfoBean = parentFcReplyBean.getCreator();
                    String receiver = StringUtils.handleTextName(ContactsController.formatName(fcUserInfoBean.getFirstName(), fcUserInfoBean.getLastName()), 12);
                    FcChildReplyListDialog.this.listener.onChildReplyClick(v, receiver, FcChildReplyListDialog.this.mChildReplyListAdapter.getParentFcReplyBean(), FcChildReplyListDialog.this.mChildReplyListAdapter.getParentFcReplyPosition(), -1, false);
                }
            }
        });
        SmartRefreshLayout smartRefreshLayout = (SmartRefreshLayout) view.findViewById(R.attr.smartRefreshLayout);
        this.mChildRefreshLayout = smartRefreshLayout;
        smartRefreshLayout.setEnableRefresh(false);
        this.mChildRefreshLayout.setEnableLoadMore(false);
        this.mChildRefreshLayout.setOnLoadMoreListener(new OnRefreshLoadMoreListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcChildReplyListDialog.4
            @Override // com.scwang.smartrefresh.layout.listener.OnLoadMoreListener
            public void onLoadMore(RefreshLayout refreshLayout) {
                if (FcChildReplyListDialog.this.listener != null) {
                    FcChildReplyListDialog.this.listener.onReplyLoadMoreData(FcChildReplyListDialog.this.mChildReplyListAdapter.getParentFcReplyBean(), FcChildReplyListDialog.this.mChildReplyListAdapter.getParentFcReplyPosition());
                }
            }

            @Override // com.scwang.smartrefresh.layout.listener.OnRefreshListener
            public void onRefresh(RefreshLayout refreshLayout) {
            }
        });
        this.rvReplyList = (RecyclerView) view.findViewById(R.attr.rv_reply_list);
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(getContext(), 1, false);
        this.layoutManager = linearLayoutManager;
        this.rvReplyList.setLayoutManager(linearLayoutManager);
        FcDialogChildReplyAdapter fcDialogChildReplyAdapter = new FcDialogChildReplyAdapter(new ArrayList(), getContext(), 0, this.listener);
        this.mChildReplyListAdapter = fcDialogChildReplyAdapter;
        this.rvReplyList.setAdapter(fcDialogChildReplyAdapter);
        this.containerView.addView(view, LayoutHelper.createFrame(-1, -2.0f));
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected boolean canDismissWithTouchOutside() {
        return false;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected boolean canDismissWithSwipe() {
        return false;
    }

    public FcDialogChildReplyAdapter getChildReplyListAdapter() {
        return this.mChildReplyListAdapter;
    }

    public void setParentFcReplyData(FcReplyBean parentFcReplyBean, int parentFcReplyPosition) {
        FcDialogChildReplyAdapter fcDialogChildReplyAdapter = this.mChildReplyListAdapter;
        if (fcDialogChildReplyAdapter != null) {
            fcDialogChildReplyAdapter.setFcReplyBean(parentFcReplyBean, parentFcReplyPosition);
        }
    }

    public void loadData(ArrayList<FcReplyBean> list, int pageNo) {
        if (this.mChildReplyListAdapter != null) {
            if (pageNo == 0) {
                if (list != null && list.size() != 0) {
                    if (list.size() < 20) {
                        this.mChildRefreshLayout.setEnableLoadMore(false);
                    } else {
                        this.mChildRefreshLayout.setEnableLoadMore(true);
                    }
                    ArrayList<FcReplyBean> temp = new ArrayList<>();
                    temp.add(new FcReplyBean());
                    temp.addAll(list);
                    if (list.size() < 20) {
                        temp.add(new FcReplyBean());
                    }
                    this.mChildReplyListAdapter.refresh(temp);
                    return;
                }
                this.mChildRefreshLayout.setEnableLoadMore(false);
                return;
            }
            if (list == null) {
                list = new ArrayList<>();
            }
            if (list.size() < 20) {
                list.add(new FcReplyBean());
                this.mChildRefreshLayout.finishLoadMore(0);
                this.mChildRefreshLayout.setEnableLoadMore(false);
            }
            this.mChildReplyListAdapter.loadMore(list);
        }
    }

    public void doLike(int position, boolean isLike, FcLikeBean data) {
        View viewByPosition = this.layoutManager.findViewByPosition(position);
        MryTextView btnLike = null;
        if (viewByPosition != null && (btnLike = (MryTextView) viewByPosition.findViewById(R.attr.btn_like)) != null) {
            btnLike.setClickable(true);
        }
        if (data != null) {
            KLog.d("------position" + position + "  " + isLike);
            FcReplyBean fcReplyBean = this.mChildReplyListAdapter.get(position);
            fcReplyBean.setHasThumb(isLike);
            if (isLike) {
                fcReplyBean.setThumbUp(this.mChildReplyListAdapter.get(position).getThumbUp() + 1);
            } else {
                fcReplyBean.setThumbUp(this.mChildReplyListAdapter.get(position).getThumbUp() - 1);
            }
            if (btnLike != null) {
                btnLike.setText(fcReplyBean.getThumbUp() > 0 ? String.valueOf(fcReplyBean.getThumbUp()) : "0");
                btnLike.setSelected(isLike);
            }
        }
    }

    public void doReply(FcReplyBean data) {
        FcDialogChildReplyAdapter fcDialogChildReplyAdapter = this.mChildReplyListAdapter;
        if (fcDialogChildReplyAdapter != null) {
            if (fcDialogChildReplyAdapter.getFooterSize() != 0) {
                this.mChildReplyListAdapter.getDataList().add(this.mChildReplyListAdapter.getItemCount() - 1, data);
                this.mChildReplyListAdapter.notifyItemInserted(r0.getItemCount() - 1);
                this.mChildReplyListAdapter.notifyItemRangeChanged(r0.getItemCount() - 1, this.mChildReplyListAdapter.getFooterSize());
                return;
            }
            ArrayList<FcReplyBean> moreList = new ArrayList<>();
            moreList.add(data);
            this.mChildReplyListAdapter.loadMore(moreList);
        }
    }

    public void doDeleteReply(int position) {
        FcReplyBean fcReplyBean = this.mChildReplyListAdapter.getParentFcReplyBean();
        if (fcReplyBean != null) {
            fcReplyBean.setSubComments(fcReplyBean.getSubComments() - 1);
            this.mChildReplyListAdapter.setParentFcReplyBean(fcReplyBean);
        }
        if (position < this.mChildReplyListAdapter.getItemCount()) {
            this.mChildReplyListAdapter.getDataList().remove(position);
            this.mChildReplyListAdapter.notifyItemRemoved(position);
            FcDialogChildReplyAdapter fcDialogChildReplyAdapter = this.mChildReplyListAdapter;
            fcDialogChildReplyAdapter.notifyItemRangeChanged(position, fcDialogChildReplyAdapter.getItemCount() - position);
        }
    }

    public ArrayList<FcReplyBean> getRealDataList() {
        ArrayList<FcReplyBean> temp = null;
        FcDialogChildReplyAdapter fcDialogChildReplyAdapter = this.mChildReplyListAdapter;
        if (fcDialogChildReplyAdapter != null && fcDialogChildReplyAdapter.getDataList() != null) {
            List<FcReplyBean> dataList = this.mChildReplyListAdapter.getDataList();
            temp = new ArrayList<>(dataList);
            if (this.mChildReplyListAdapter.getFooterSize() != 0) {
                temp.remove(temp.size() - 1);
            }
            temp.remove(0);
        }
        return temp;
    }

    public void setListener(ChildReplyListListener listener) {
        FcDialogChildReplyAdapter fcDialogChildReplyAdapter;
        this.listener = listener;
        if (listener != null && (fcDialogChildReplyAdapter = this.mChildReplyListAdapter) != null) {
            fcDialogChildReplyAdapter.setListener(listener);
        }
    }
}
