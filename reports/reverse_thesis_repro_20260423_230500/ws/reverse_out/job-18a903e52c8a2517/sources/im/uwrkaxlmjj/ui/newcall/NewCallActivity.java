package im.uwrkaxlmjj.ui.newcall;

import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.text.SpannableString;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.socks.library.KLog;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.ColorRelativeLayout;
import im.uwrkaxlmjj.ui.components.ColorTextView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.components.voip.VoIPHelper;
import im.uwrkaxlmjj.ui.dialogs.DialogCommonList;
import im.uwrkaxlmjj.ui.hcells.MryDividerCell;
import im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity;
import im.uwrkaxlmjj.ui.hui.decoration.TopBottomDecoration;
import im.uwrkaxlmjj.ui.hui.visualcall.VisualCallActivity;
import im.uwrkaxlmjj.ui.hviews.MryEmptyTextProgressView;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
@Deprecated
public class NewCallActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate, View.OnClickListener {
    private static final int TYPE_IN = 1;
    private static final int TYPE_MISSED = 2;
    private static final int TYPE_OUT = 0;
    private MryEmptyTextProgressView emptyView;
    private boolean endReached;
    private boolean firstLoaded;
    private TLRPC.User lastCallUser;
    private LinearLayoutManager layoutManager;
    private SlidingItemMenuRecyclerView listView;
    private ListAdapter listViewAdapter;
    private boolean loading;
    private ImageView mIvAdd;
    private ImageView mIvBack;
    private RelativeLayout mRlBack;
    private TextView m_tvAll;
    private TextView m_tvCancel;
    private TextView m_tvCurrent;
    private View tabContainer;
    private ArrayList<CallLogRow> calls = new ArrayList<>();
    private ArrayList<CallLogRow> allCalls = new ArrayList<>();
    private ArrayList<CallLogRow> cancelCalls = new ArrayList<>();
    private View.OnClickListener callBtnClickListener = new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.newcall.-$$Lambda$NewCallActivity$M7OoT8KS0ABOLdjx1zRfuZ1vd7Y
        @Override // android.view.View.OnClickListener
        public final void onClick(View view) {
            this.f$0.lambda$new$6$NewCallActivity(view);
        }
    };

    /* JADX INFO: Access modifiers changed from: private */
    class CallLogRow {
        public List<TLRPC.Message> calls;
        public int type;
        public TLRPC.User user;

        private CallLogRow() {
        }

        /* synthetic */ CallLogRow(NewCallActivity x0, AnonymousClass1 x1) {
            this();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        getCalls(0, 50);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.didReceiveNewMessages);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messagesDeleted);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.didReceiveNewMessages);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messagesDeleted);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setAddToContainer(false);
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_new_call, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initTitleBar();
        initView(context);
        return this.fragmentView;
    }

    private void initTitleBar() {
        FrameLayout flTitleBarContainer = (FrameLayout) this.fragmentView.findViewById(R.attr.fl_title_bar_container);
        flTitleBarContainer.setBackground(this.defaultActionBarBackgroundDrawable);
        LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) flTitleBarContainer.getLayoutParams();
        layoutParams.height = ActionBar.getCurrentActionBarHeight() + AndroidUtilities.statusBarHeight;
        flTitleBarContainer.setLayoutParams(layoutParams);
        flTitleBarContainer.setPadding(0, AndroidUtilities.statusBarHeight, 0, 0);
        this.mRlBack = (RelativeLayout) this.fragmentView.findViewById(R.attr.rl_back);
        this.mIvBack = (ImageView) this.fragmentView.findViewById(R.attr.iv_back);
        this.mIvAdd = (ImageView) this.fragmentView.findViewById(R.attr.iv_add);
        this.mIvBack.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_actionBarDefaultIcon), PorterDuff.Mode.MULTIPLY));
        this.mIvBack.setBackground(Theme.createSelectorDrawable(Theme.getColor(Theme.key_actionBarDefaultSelector)));
        this.mIvAdd.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_actionBarDefaultIcon), PorterDuff.Mode.MULTIPLY));
        this.mIvAdd.setBackground(Theme.createSelectorDrawable(Theme.getColor(Theme.key_actionBarDefaultSelector)));
        this.m_tvAll = (TextView) this.fragmentView.findViewById(R.attr.tv_all_call);
        this.m_tvCancel = (TextView) this.fragmentView.findViewById(R.attr.tv_cancel_call);
        this.m_tvCurrent = this.m_tvAll;
    }

    private void initView(Context context) {
        this.tabContainer = this.fragmentView.findViewById(R.attr.tabContainer);
        FrameLayout flContainer = (FrameLayout) this.fragmentView.findViewById(R.attr.fl_container);
        flContainer.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        MryEmptyTextProgressView mryEmptyTextProgressView = new MryEmptyTextProgressView(context);
        this.emptyView = mryEmptyTextProgressView;
        mryEmptyTextProgressView.setText(LocaleController.getString("NoCallRecords", R.string.NoCallRecords));
        this.emptyView.setTopImage(R.id.img_empty_default);
        flContainer.addView(this.emptyView, LayoutHelper.createFrame(-1, -1.0f));
        SlidingItemMenuRecyclerView slidingItemMenuRecyclerView = new SlidingItemMenuRecyclerView(context);
        this.listView = slidingItemMenuRecyclerView;
        slidingItemMenuRecyclerView.addItemDecoration(new TopBottomDecoration());
        this.listView.setEmptyView(this.emptyView);
        this.listView.setOverScrollMode(2);
        this.listView.setVerticalScrollBarEnabled(false);
        SlidingItemMenuRecyclerView slidingItemMenuRecyclerView2 = this.listView;
        ListAdapter listAdapter = new ListAdapter(context);
        this.listViewAdapter = listAdapter;
        slidingItemMenuRecyclerView2.setAdapter(listAdapter);
        SlidingItemMenuRecyclerView slidingItemMenuRecyclerView3 = this.listView;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context, 1, false);
        this.layoutManager = linearLayoutManager;
        slidingItemMenuRecyclerView3.setLayoutManager(linearLayoutManager);
        this.listView.setVerticalScrollbarPosition(LocaleController.isRTL ? 1 : 2);
        this.listView.setGlowColor(Theme.getColor(Theme.key_avatar_backgroundActionBarBlue));
        flContainer.addView(this.listView, LayoutHelper.createFrame(-1, -2.0f));
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.newcall.-$$Lambda$NewCallActivity$Y2a4k75na7LKuDWhP1tVKK2Z0Gk
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initView$0$NewCallActivity(view, i);
            }
        });
        this.listView.setOnScrollListener(new AnonymousClass1());
        if (this.loading) {
            this.emptyView.showProgress();
        } else {
            this.emptyView.showTextView();
        }
        initListener();
        changeTabState(this.m_tvCurrent);
    }

    public /* synthetic */ void lambda$initView$0$NewCallActivity(View view, int position) {
        if (position < 0 || position >= this.calls.size()) {
            return;
        }
        CallLogRow row = this.calls.get(position);
        showAlert(row.user);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.newcall.NewCallActivity$1, reason: invalid class name */
    class AnonymousClass1 extends RecyclerView.OnScrollListener {
        AnonymousClass1() {
        }

        @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
        public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
            int firstVisibleItem = NewCallActivity.this.layoutManager.findFirstVisibleItemPosition();
            int visibleItemCount = firstVisibleItem == -1 ? 0 : Math.abs(NewCallActivity.this.layoutManager.findLastVisibleItemPosition() - firstVisibleItem) + 1;
            if (visibleItemCount > 0) {
                int totalItemCount = NewCallActivity.this.listViewAdapter.getItemCount();
                if (!NewCallActivity.this.endReached && !NewCallActivity.this.loading && !NewCallActivity.this.calls.isEmpty() && firstVisibleItem + visibleItemCount >= totalItemCount - 5) {
                    final CallLogRow row = (CallLogRow) NewCallActivity.this.calls.get(NewCallActivity.this.calls.size() - 1);
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.newcall.-$$Lambda$NewCallActivity$1$etv1MsUyAXPbXOfbxczGEE99KA0
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$onScrolled$0$NewCallActivity$1(row);
                        }
                    });
                }
            }
        }

        public /* synthetic */ void lambda$onScrolled$0$NewCallActivity$1(CallLogRow row) {
            NewCallActivity.this.getCalls(row.calls.get(row.calls.size() - 1).id, 100);
        }
    }

    private void initListener() {
        this.m_tvAll.setOnClickListener(this);
        this.m_tvCancel.setOnClickListener(this);
        this.mRlBack.setOnClickListener(this);
        this.mIvAdd.setOnClickListener(this);
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View v) {
        switch (v.getId()) {
            case R.attr.iv_add /* 2131296779 */:
                presentFragment(new AddNewCallActivity());
                break;
            case R.attr.rl_back /* 2131297143 */:
                finishFragment();
                break;
            case R.attr.tv_all_call /* 2131297712 */:
                if (this.m_tvCurrent.getId() != v.getId()) {
                    changeTabState(v);
                    this.m_tvCurrent = this.m_tvAll;
                    this.emptyView.setTopImage(R.id.img_empty_default);
                    this.emptyView.setText(LocaleController.getString("NoCallRecords", R.string.NoCallRecords));
                    if (this.listViewAdapter != null) {
                        this.calls.clear();
                        this.calls.addAll(this.allCalls);
                        this.listViewAdapter.notifyDataSetChanged();
                    }
                }
                break;
            case R.attr.tv_cancel_call /* 2131297726 */:
                if (this.m_tvCurrent.getId() != v.getId()) {
                    changeTabState(v);
                    this.m_tvCurrent = this.m_tvCancel;
                    this.emptyView.setText(LocaleController.getString("NoCancelCallLog", R.string.NoCancelCallLog));
                    ListAdapter listAdapter = this.listViewAdapter;
                    if (listAdapter != null && listAdapter != null) {
                        this.calls.clear();
                        this.calls.addAll(this.cancelCalls);
                        this.listViewAdapter.notifyDataSetChanged();
                        break;
                    }
                }
                break;
        }
    }

    private void changeTabState(View view) {
        if (view.getId() == this.m_tvAll.getId()) {
            if (this.tabContainer.getBackground() != null) {
                this.tabContainer.getBackground().setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText), PorterDuff.Mode.SRC_IN));
            }
            this.m_tvAll.setTextColor(-1);
            this.m_tvAll.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), 0.0f, AndroidUtilities.dp(5.0f), 0.0f, Theme.getColor(Theme.key_windowBackgroundWhiteBlueText)));
            this.m_tvCancel.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
            this.m_tvCancel.setBackground(Theme.createRoundRectDrawable(0.0f, AndroidUtilities.dp(5.0f), 0.0f, AndroidUtilities.dp(5.0f), 0));
            return;
        }
        if (this.tabContainer.getBackground() != null) {
            this.tabContainer.getBackground().setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText), PorterDuff.Mode.SRC_IN));
        }
        this.m_tvCancel.setTextColor(-1);
        this.m_tvCancel.setBackground(Theme.createRoundRectDrawable(0.0f, AndroidUtilities.dp(5.0f), 0.0f, AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhiteBlueText)));
        this.m_tvAll.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
        this.m_tvAll.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), 0.0f, AndroidUtilities.dp(5.0f), 0.0f, 0));
    }

    /* JADX INFO: Access modifiers changed from: private */
    class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return NewCallActivity.this.calls.size();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, final int position) {
            Drawable drawable;
            Drawable drawable2;
            Drawable drawable3;
            ColorTextView tvCallType = (ColorTextView) holder.itemView.findViewById(R.attr.tv_call_type);
            ColorTextView tvName = (ColorTextView) holder.itemView.findViewById(R.attr.tv_nick_name);
            final CallLogRow row = (CallLogRow) NewCallActivity.this.calls.get(position);
            TLRPC.Message last = row.calls.get(0);
            String ldir = LocaleController.isRTL ? "\u202b" : "";
            SpannableString subtitle = new SpannableString(ldir + "  " + LocaleController.formatDateCallLog(last.date));
            StringBuilder sb = new StringBuilder();
            sb.append("onbindview = ");
            sb.append(row.calls.get(0).date);
            sb.append(" ");
            sb.append(row.calls.size() > 1 ? Integer.valueOf(row.calls.get(1).date) : "");
            KLog.d(sb.toString());
            int i = row.type;
            if (i == 0) {
                if ((last.action.flags & 4) != 0) {
                    drawable = this.mContext.getResources().getDrawable(R.drawable.new_call_video_out);
                    drawable.setBounds(0, 0, 42, 42);
                    tvCallType.setText(LocaleController.getString("new_call_video_out", R.string.new_call_video_out));
                } else {
                    drawable = this.mContext.getResources().getDrawable(R.id.ic_new_call_out);
                    drawable.setBounds(0, 0, 42, 42);
                    tvCallType.setText(LocaleController.getString("new_call_voice_out", R.string.new_call_voice_out));
                }
                tvCallType.setCompoundDrawables(drawable, null, null, null);
                tvName.setTextColor(Theme.ACTION_BAR_MEDIA_PICKER_COLOR);
            } else if (i == 1) {
                if (last.action.duration != -3 && last.action.duration != -4 && last.action.duration != -5) {
                    if ((last.action.flags & 4) != 0) {
                        drawable2 = this.mContext.getResources().getDrawable(R.drawable.new_call_video_in);
                        drawable2.setBounds(0, 0, 42, 42);
                        tvCallType.setText(LocaleController.getString("new_call_video_in", R.string.new_call_video_in));
                    } else {
                        drawable2 = this.mContext.getResources().getDrawable(R.id.ic_new_call_in);
                        drawable2.setBounds(0, 0, 42, 42);
                        tvCallType.setText(LocaleController.getString("new_call_voice_in", R.string.new_call_voice_in));
                    }
                    tvName.setTextColor(Theme.ACTION_BAR_MEDIA_PICKER_COLOR);
                } else {
                    if ((last.action.flags & 4) == 0) {
                        drawable2 = this.mContext.getResources().getDrawable(R.id.ic_new_call_cancel);
                        drawable2.setBounds(0, 0, 42, 42);
                        tvCallType.setText(LocaleController.getString("new_call_voice_no_answer", R.string.new_call_voice_no_answer));
                    } else {
                        drawable2 = this.mContext.getResources().getDrawable(R.drawable.new_call_video_no_answer);
                        drawable2.setBounds(0, 0, 42, 42);
                        tvCallType.setText(LocaleController.getString("new_call_video_no_answer", R.string.new_call_video_no_answer));
                    }
                    tvName.setTextColor(-570319);
                }
                tvCallType.setCompoundDrawables(drawable2, null, null, null);
            } else if (i == 2) {
                if ((last.action.flags & 4) == 0) {
                    drawable3 = this.mContext.getResources().getDrawable(R.id.ic_new_call_cancel);
                    drawable3.setBounds(0, 0, 42, 42);
                    tvCallType.setText(LocaleController.getString("new_call_voice_no_answer", R.string.new_call_voice_no_answer));
                } else {
                    drawable3 = this.mContext.getResources().getDrawable(R.drawable.new_call_video_no_answer);
                    drawable3.setBounds(0, 0, 42, 42);
                    tvCallType.setText(LocaleController.getString("new_call_video_no_answer", R.string.new_call_video_no_answer));
                }
                tvName.setTextColor(-570319);
                tvCallType.setCompoundDrawables(drawable3, null, null, null);
            }
            ((ColorTextView) holder.itemView.findViewById(R.attr.tv_date)).setText(subtitle);
            AvatarDrawable avatarDrawable = new AvatarDrawable();
            avatarDrawable.setInfo(row.user);
            BackupImageView iv_header = (BackupImageView) holder.itemView.findViewById(R.attr.iv_head_img);
            iv_header.setImage(ImageLocation.getForUser(row.user, false), "50_50", avatarDrawable, row.user);
            iv_header.setRoundRadius(AndroidUtilities.dp(7.5f));
            holder.itemView.findViewById(R.attr.iv_more).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.newcall.-$$Lambda$NewCallActivity$ListAdapter$VDUrQC2iNXTlzW3nXi_Pko2JHAM
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$onBindViewHolder$0$NewCallActivity$ListAdapter(row, view);
                }
            });
            holder.itemView.findViewById(R.attr.iv_more).setTag(row);
            tvName.setText(UserObject.getName(row.user));
            ColorRelativeLayout rlContent = (ColorRelativeLayout) holder.itemView.findViewById(R.attr.rl_content);
            MryDividerCell divider = (MryDividerCell) holder.itemView.findViewById(R.attr.divider);
            if (getItemCount() == 1) {
                rlContent.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                divider.setVisibility(8);
            } else if (position == 0) {
                rlContent.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
            } else if (position == getItemCount() - 1) {
                divider.setVisibility(8);
                rlContent.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
            } else {
                rlContent.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            }
            TextView btnDelete = (TextView) holder.itemView.findViewById(R.attr.btnDelete);
            btnDelete.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.newcall.-$$Lambda$NewCallActivity$ListAdapter$V6JL_Szzxt9vj79hcpcRXXcwTqM
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$onBindViewHolder$2$NewCallActivity$ListAdapter(position, row, view);
                }
            });
        }

        public /* synthetic */ void lambda$onBindViewHolder$0$NewCallActivity$ListAdapter(CallLogRow row, View v) {
            Bundle bundle = new Bundle();
            bundle.putInt("user_id", row.user.id);
            NewCallActivity.this.presentFragment(new NewProfileActivity(bundle));
        }

        public /* synthetic */ void lambda$onBindViewHolder$2$NewCallActivity$ListAdapter(int position, final CallLogRow row, View v) {
            if (position >= 0 && position < NewCallActivity.this.calls.size()) {
                final CallLogRow callLogRow = (CallLogRow) NewCallActivity.this.calls.get(position);
                ArrayList<String> items = new ArrayList<>();
                items.add(LocaleController.getString("Delete", R.string.Delete));
                if (VoIPHelper.canRateCall((TLRPC.TL_messageActionPhoneCall) callLogRow.calls.get(0).action)) {
                    items.add(LocaleController.getString("CallMessageReportProblem", R.string.CallMessageReportProblem));
                }
                new AlertDialog.Builder(NewCallActivity.this.getParentActivity()).setTitle(LocaleController.getString("Calls", R.string.Calls)).setItems((CharSequence[]) items.toArray(new String[0]), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.newcall.-$$Lambda$NewCallActivity$ListAdapter$eFnC0rb3cWB44638S_BN7qos5t4
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$1$NewCallActivity$ListAdapter(row, callLogRow, dialogInterface, i);
                    }
                }).show();
            }
        }

        public /* synthetic */ void lambda$null$1$NewCallActivity$ListAdapter(CallLogRow row, CallLogRow callLogRow, DialogInterface dialog, int which) {
            if (which == 0) {
                NewCallActivity.this.confirmAndDelete(row);
            } else if (which == 1) {
                VoIPHelper.showRateAlert(NewCallActivity.this.getParentActivity(), (TLRPC.TL_messageActionPhoneCall) callLogRow.calls.get(0).action);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return true;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            return position;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_new_call, parent, false);
            RecyclerView.LayoutParams layoutParams = new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(71.0f));
            layoutParams.leftMargin = AndroidUtilities.dp(10.0f);
            layoutParams.rightMargin = AndroidUtilities.dp(10.0f);
            view.setLayoutParams(layoutParams);
            ((ImageView) view.findViewById(R.attr.iv_more)).setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_featuredStickers_addButton), PorterDuff.Mode.MULTIPLY));
            ((BackupImageView) view.findViewById(R.attr.iv_head_img)).setRoundRadius(AndroidUtilities.dp(7.5f));
            return new RecyclerListView.Holder(view);
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        ListAdapter listAdapter;
        if (id == NotificationCenter.didReceiveNewMessages && this.firstLoaded) {
            boolean scheduled = ((Boolean) args[2]).booleanValue();
            if (scheduled) {
                return;
            }
            ArrayList<MessageObject> arr = (ArrayList) args[1];
            for (MessageObject msg : arr) {
                if (msg.messageOwner.action instanceof TLRPC.TL_messageActionPhoneCall) {
                    int userID = msg.messageOwner.from_id == UserConfig.getInstance(this.currentAccount).getClientUserId() ? msg.messageOwner.to_id.user_id : msg.messageOwner.from_id;
                    int callType = msg.messageOwner.from_id == UserConfig.getInstance(this.currentAccount).getClientUserId() ? 0 : 1;
                    TLRPC.PhoneCallDiscardReason reason = msg.messageOwner.action.reason;
                    if (callType == 1 && ((reason instanceof TLRPC.TL_phoneCallDiscardReasonMissed) || (reason instanceof TLRPC.TL_phoneCallDiscardReasonBusy) || msg.messageOwner.action.duration == -3 || msg.messageOwner.action.duration == -4 || msg.messageOwner.action.duration == -5)) {
                        callType = 2;
                    }
                    if (this.calls.size() > 0) {
                        CallLogRow topRow = this.calls.get(0);
                        if (topRow.user.id == userID && topRow.type == callType) {
                            if (this.m_tvCurrent == this.m_tvAll || topRow.type == 2) {
                                topRow.calls.add(0, msg.messageOwner);
                                this.listViewAdapter.notifyItemChanged(0);
                            }
                        }
                    }
                    CallLogRow row = new CallLogRow(this, null);
                    row.calls = new ArrayList();
                    row.calls.add(msg.messageOwner);
                    row.user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(userID));
                    row.type = callType;
                    if ((this.m_tvCurrent == this.m_tvAll || row.type == 2) && !this.calls.contains(row)) {
                        this.calls.add(0, row);
                        this.listViewAdapter.notifyItemInserted(0);
                    }
                    if (!this.allCalls.contains(row)) {
                        this.allCalls.add(0, row);
                    }
                    if (row.type == 2 && !this.cancelCalls.contains(row)) {
                        this.cancelCalls.add(0, row);
                    }
                }
            }
            return;
        }
        if (id == NotificationCenter.messagesDeleted && this.firstLoaded) {
            boolean scheduled2 = ((Boolean) args[2]).booleanValue();
            if (scheduled2) {
                return;
            }
            boolean didChange = false;
            ArrayList<Integer> ids = (ArrayList) args[0];
            Iterator<CallLogRow> itrtr = this.calls.iterator();
            while (itrtr.hasNext()) {
                CallLogRow row2 = itrtr.next();
                Iterator<TLRPC.Message> msgs = row2.calls.iterator();
                while (msgs.hasNext()) {
                    if (ids.contains(Integer.valueOf(msgs.next().id))) {
                        didChange = true;
                        msgs.remove();
                    }
                }
                if (row2.calls.size() == 0) {
                    itrtr.remove();
                    this.allCalls.remove(row2);
                    if (this.m_tvCurrent == this.m_tvCancel) {
                        this.cancelCalls.remove(row2);
                    }
                }
            }
            if (didChange && (listAdapter = this.listViewAdapter) != null) {
                listAdapter.notifyDataSetChanged();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void getCalls(int max_id, int count) {
        if (this.loading) {
            return;
        }
        this.loading = true;
        MryEmptyTextProgressView mryEmptyTextProgressView = this.emptyView;
        if (mryEmptyTextProgressView != null && !this.firstLoaded) {
            mryEmptyTextProgressView.showProgress();
        }
        ListAdapter listAdapter = this.listViewAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
        TLRPC.TL_messages_search req = new TLRPC.TL_messages_search();
        req.limit = count;
        req.peer = new TLRPC.TL_inputPeerEmpty();
        req.filter = new TLRPC.TL_inputMessagesFilterPhoneCalls();
        req.q = "";
        req.offset_id = max_id;
        int reqId = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.newcall.-$$Lambda$NewCallActivity$UDtluON3vCXJ5ayi6fYGTfFSw0I
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getCalls$2$NewCallActivity(tLObject, tL_error);
            }
        }, 2);
        ConnectionsManager.getInstance(this.currentAccount).bindRequestToGuid(reqId, this.classGuid);
    }

    public /* synthetic */ void lambda$getCalls$2$NewCallActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.newcall.-$$Lambda$NewCallActivity$TrBmxKWjsqo7pKOAmDw9lh5449k
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$1$NewCallActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$1$NewCallActivity(TLRPC.TL_error error, TLObject response) {
        CallLogRow currentRow;
        if (error == null) {
            SparseArray<TLRPC.User> users = new SparseArray<>();
            TLRPC.messages_Messages msgs = (TLRPC.messages_Messages) response;
            this.endReached = msgs.messages.isEmpty();
            for (int a = 0; a < msgs.users.size(); a++) {
                TLRPC.User user = msgs.users.get(a);
                users.put(user.id, user);
            }
            AnonymousClass1 anonymousClass1 = null;
            if (this.allCalls.size() > 0) {
                ArrayList<CallLogRow> arrayList = this.allCalls;
                currentRow = arrayList.get(arrayList.size() - 1);
            } else {
                currentRow = null;
            }
            for (int a2 = 0; a2 < msgs.messages.size(); a2++) {
                TLRPC.Message msg = msgs.messages.get(a2);
                if (msg.action != null && !(msg.action instanceof TLRPC.TL_messageActionHistoryClear)) {
                    int callType = msg.from_id == UserConfig.getInstance(this.currentAccount).getClientUserId() ? 0 : 1;
                    TLRPC.PhoneCallDiscardReason reason = msg.action.reason;
                    if (callType == 1 && ((reason instanceof TLRPC.TL_phoneCallDiscardReasonMissed) || (reason instanceof TLRPC.TL_phoneCallDiscardReasonBusy) || msg.action.duration == -3 || msg.action.duration == -4 || msg.action.duration == -5)) {
                        callType = 2;
                    }
                    int userID = msg.from_id == UserConfig.getInstance(this.currentAccount).getClientUserId() ? msg.to_id.user_id : msg.from_id;
                    if (currentRow == null || currentRow.user.id != userID || currentRow.type != callType) {
                        if (currentRow != null && !this.allCalls.contains(currentRow)) {
                            this.allCalls.add(currentRow);
                            if (currentRow.type == 2 && !this.cancelCalls.contains(currentRow)) {
                                this.cancelCalls.add(currentRow);
                            }
                        }
                        CallLogRow row = new CallLogRow(this, anonymousClass1);
                        row.calls = new ArrayList();
                        row.user = users.get(userID);
                        row.type = callType;
                        currentRow = row;
                    }
                    currentRow.calls.add(msg);
                }
            }
            if (currentRow != null && currentRow.calls.size() > 0 && !this.allCalls.contains(currentRow)) {
                this.allCalls.add(currentRow);
                if (currentRow.type == 2 && !this.cancelCalls.contains(currentRow)) {
                    this.cancelCalls.add(currentRow);
                }
            }
        } else {
            this.endReached = true;
        }
        this.loading = false;
        this.firstLoaded = true;
        MryEmptyTextProgressView mryEmptyTextProgressView = this.emptyView;
        if (mryEmptyTextProgressView != null) {
            mryEmptyTextProgressView.showTextView();
        }
        if (this.listViewAdapter != null) {
            this.calls.clear();
            if (this.m_tvCurrent == this.m_tvCancel) {
                this.calls.addAll(this.cancelCalls);
            } else {
                this.calls.addAll(this.allCalls);
            }
            this.listViewAdapter.notifyDataSetChanged();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void confirmAndDelete(final CallLogRow row) {
        if (getParentActivity() == null) {
            return;
        }
        new AlertDialog.Builder(getParentActivity()).setTitle(LocaleController.getString("AppName", R.string.AppName)).setMessage(LocaleController.getString("ConfirmDeleteCallLog", R.string.ConfirmDeleteCallLog)).setPositiveButton(LocaleController.getString("Delete", R.string.Delete), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.newcall.-$$Lambda$NewCallActivity$cK_dxCDk3U0PEmESmaQhdD9g-II
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$confirmAndDelete$3$NewCallActivity(row, dialogInterface, i);
            }
        }).setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null).show().setCanceledOnTouchOutside(true);
    }

    public /* synthetic */ void lambda$confirmAndDelete$3$NewCallActivity(CallLogRow row, DialogInterface dialog, int which) {
        ArrayList<Integer> ids = new ArrayList<>();
        for (TLRPC.Message msg : row.calls) {
            ids.add(Integer.valueOf(msg.id));
        }
        MessagesController.getInstance(this.currentAccount).deleteMessages(ids, null, null, 0L, 0, false, false);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        ListAdapter listAdapter = this.listViewAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    private void showAlert(final TLRPC.User user) {
        List<String> list = new ArrayList<>();
        list.add(LocaleController.getString("menu_voice_chat", R.string.menu_voice_chat));
        list.add(LocaleController.getString("menu_video_chat", R.string.menu_video_chat));
        List<Integer> list1 = new ArrayList<>();
        list1.add(Integer.valueOf(R.drawable.menu_voice_call));
        list1.add(Integer.valueOf(R.drawable.menu_video_call));
        DialogCommonList dialogCommonList = new DialogCommonList(getParentActivity(), list, list1, Color.parseColor("#222222"), new DialogCommonList.RecyclerviewItemClickCallBack() { // from class: im.uwrkaxlmjj.ui.newcall.-$$Lambda$NewCallActivity$hgB-F4I3rMuNv27ZPrub2oNMwLo
            @Override // im.uwrkaxlmjj.ui.dialogs.DialogCommonList.RecyclerviewItemClickCallBack
            public final void onRecyclerviewItemClick(int i) {
                this.f$0.lambda$showAlert$4$NewCallActivity(user, i);
            }
        }, 1);
        dialogCommonList.show();
    }

    public /* synthetic */ void lambda$showAlert$4$NewCallActivity(TLRPC.User user, int position) {
        if (position == 0) {
            if (ApplicationLoader.mbytAVideoCallBusy == 0) {
                if (user.mutual_contact) {
                    int currentConnectionState = ConnectionsManager.getInstance(this.currentAccount).getConnectionState();
                    if (currentConnectionState == 2 || currentConnectionState == 1) {
                        ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_network", R.string.visual_call_no_network));
                        return;
                    }
                    Intent intent = new Intent();
                    intent.setClass(getParentActivity(), VisualCallActivity.class);
                    intent.putExtra("CallType", 1);
                    ArrayList<Integer> ArrInputPeers = new ArrayList<>();
                    ArrInputPeers.add(Integer.valueOf(user.id));
                    intent.putExtra("ArrayUser", ArrInputPeers);
                    intent.putExtra("channel", new ArrayList());
                    getParentActivity().startActivity(intent);
                    return;
                }
                ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_friend_tip", R.string.visual_call_no_friend_tip));
                return;
            }
            ToastUtils.show((CharSequence) LocaleController.getString("visual_call_busing_tip", R.string.visual_call_busing_tip));
            return;
        }
        if (position == 1) {
            if (ApplicationLoader.mbytAVideoCallBusy == 0) {
                if (user.mutual_contact) {
                    int currentConnectionState2 = ConnectionsManager.getInstance(this.currentAccount).getConnectionState();
                    if (currentConnectionState2 == 2 || currentConnectionState2 == 1) {
                        ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_network", R.string.visual_call_no_network));
                        return;
                    }
                    Intent intent2 = new Intent();
                    intent2.setClass(getParentActivity(), VisualCallActivity.class);
                    intent2.putExtra("CallType", 2);
                    ArrayList<Integer> ArrInputPeers2 = new ArrayList<>();
                    ArrInputPeers2.add(Integer.valueOf(user.id));
                    intent2.putExtra("ArrayUser", ArrInputPeers2);
                    intent2.putExtra("channel", new ArrayList());
                    getParentActivity().startActivity(intent2);
                    return;
                }
                ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_friend_tip", R.string.visual_call_no_friend_tip));
                return;
            }
            ToastUtils.show((CharSequence) LocaleController.getString("visual_call_busing_tip", R.string.visual_call_busing_tip));
        }
    }

    public /* synthetic */ void lambda$new$6$NewCallActivity(View v) {
        final CallLogRow row = (CallLogRow) v.getTag();
        List<String> list = new ArrayList<>();
        list.add(LocaleController.getString("menu_voice_chat", R.string.menu_voice_chat));
        list.add(LocaleController.getString("menu_video_chat", R.string.menu_video_chat));
        List<Integer> list1 = new ArrayList<>();
        list1.add(Integer.valueOf(R.drawable.menu_voice_call));
        list1.add(Integer.valueOf(R.drawable.menu_video_call));
        DialogCommonList dialogCommonList = new DialogCommonList(getParentActivity(), list, list1, Color.parseColor("#222222"), new DialogCommonList.RecyclerviewItemClickCallBack() { // from class: im.uwrkaxlmjj.ui.newcall.-$$Lambda$NewCallActivity$_iRtCtzArKxhzWFndoxFyIqLVN8
            @Override // im.uwrkaxlmjj.ui.dialogs.DialogCommonList.RecyclerviewItemClickCallBack
            public final void onRecyclerviewItemClick(int i) {
                this.f$0.lambda$null$5$NewCallActivity(row, i);
            }
        }, 1);
        dialogCommonList.show();
    }

    public /* synthetic */ void lambda$null$5$NewCallActivity(CallLogRow row, int position) {
        if (position == 0) {
            if (ApplicationLoader.mbytAVideoCallBusy == 0) {
                if (row.user.mutual_contact) {
                    int currentConnectionState = ConnectionsManager.getInstance(this.currentAccount).getConnectionState();
                    if (currentConnectionState == 2 || currentConnectionState == 1) {
                        ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_network", R.string.visual_call_no_network));
                        return;
                    }
                    Intent intent = new Intent();
                    intent.setClass(getParentActivity(), VisualCallActivity.class);
                    intent.putExtra("CallType", 1);
                    ArrayList<Integer> ArrInputPeers = new ArrayList<>();
                    ArrInputPeers.add(Integer.valueOf(row.user.id));
                    intent.putExtra("ArrayUser", ArrInputPeers);
                    intent.putExtra("channel", new ArrayList());
                    getParentActivity().startActivity(intent);
                    return;
                }
                ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_friend_tip", R.string.visual_call_no_friend_tip));
                return;
            }
            ToastUtils.show((CharSequence) LocaleController.getString("visual_call_busing_tip", R.string.visual_call_busing_tip));
            return;
        }
        if (position == 1) {
            if (ApplicationLoader.mbytAVideoCallBusy == 0) {
                if (row.user.mutual_contact) {
                    int currentConnectionState2 = ConnectionsManager.getInstance(this.currentAccount).getConnectionState();
                    if (currentConnectionState2 == 2 || currentConnectionState2 == 1) {
                        ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_network", R.string.visual_call_no_network));
                        return;
                    }
                    Intent intent2 = new Intent();
                    intent2.setClass(getParentActivity(), VisualCallActivity.class);
                    intent2.putExtra("CallType", 2);
                    ArrayList<Integer> ArrInputPeers2 = new ArrayList<>();
                    ArrInputPeers2.add(Integer.valueOf(row.user.id));
                    intent2.putExtra("ArrayUser", ArrInputPeers2);
                    intent2.putExtra("channel", new ArrayList());
                    getParentActivity().startActivity(intent2);
                    return;
                }
                ToastUtils.show((CharSequence) LocaleController.getString("visual_call_no_friend_tip", R.string.visual_call_no_friend_tip));
                return;
            }
            ToastUtils.show((CharSequence) LocaleController.getString("visual_call_busing_tip", R.string.visual_call_busing_tip));
        }
    }
}
