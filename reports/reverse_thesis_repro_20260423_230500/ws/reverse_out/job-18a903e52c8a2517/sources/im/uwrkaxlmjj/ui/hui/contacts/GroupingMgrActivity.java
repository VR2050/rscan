package im.uwrkaxlmjj.ui.hui.contacts;

import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Canvas;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.text.Editable;
import android.text.InputFilter;
import android.text.Spanned;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.Display;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.LinearLayout;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import butterknife.BindView;
import butterknife.OnClick;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.dialogs.WalletDialog;
import im.uwrkaxlmjj.ui.hcells.MryDividerCell;
import im.uwrkaxlmjj.ui.hui.adapter.grouping.Artist;
import im.uwrkaxlmjj.ui.hui.adapter.grouping.Genre;
import im.uwrkaxlmjj.ui.hui.contacts.AddGroupingUserActivity;
import im.uwrkaxlmjj.ui.hui.contacts.GroupingMgrActivity;
import im.uwrkaxlmjj.ui.hviews.MryEditText;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.hviews.slidemenu.SwipeLayout;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class GroupingMgrActivity extends BaseFragment {
    private static final int item_done = 1;
    private List<Integer> defaultOrders;
    private List<Integer> deletedGroupIds;
    private List<Genre> genres = new ArrayList();
    private GroupManageAdapter mAdapter;

    @BindView(R.attr.rcvList)
    RecyclerListView mRcvList;

    @BindView(R.attr.tv_add_group)
    MryTextView mTvAddGroup;
    private int requestCount;
    private int requestDoneCount;

    public void setGenres(List<Genre> genres) {
        if (this.requestCount != 0) {
            return;
        }
        this.genres = new ArrayList(genres);
        this.deletedGroupIds = new ArrayList();
        this.defaultOrders = new ArrayList();
        for (Genre genre : genres) {
            this.defaultOrders.add(Integer.valueOf(genre.getOrderId()));
        }
        GroupManageAdapter groupManageAdapter = this.mAdapter;
        if (groupManageAdapter != null) {
            groupManageAdapter.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        this.swipeBackEnabled = false;
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_grouping_mgr_layout, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        useButterKnife();
        initActionbar();
        initView();
        return this.fragmentView;
    }

    private void initActionbar() {
        this.actionBar.setCastShadows(false);
        this.actionBar.setTitle(LocaleController.getString("ManageGrouping", R.string.ManageGrouping));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.contacts.GroupingMgrActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    if (GroupingMgrActivity.this.isOrderChanged() || !GroupingMgrActivity.this.deletedGroupIds.isEmpty()) {
                        GroupingMgrActivity.this.showSaveDialog();
                        return;
                    } else {
                        GroupingMgrActivity.this.finishFragment();
                        return;
                    }
                }
                if (id == 1) {
                    if (GroupingMgrActivity.this.isOrderChanged() || !GroupingMgrActivity.this.deletedGroupIds.isEmpty()) {
                        GroupingMgrActivity.this.saveChanged();
                    } else {
                        GroupingMgrActivity.this.finishFragment();
                    }
                }
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        MryTextView tvOkView = new MryTextView(getParentActivity());
        tvOkView.setText(LocaleController.getString("Done", R.string.Done));
        tvOkView.setTextSize(1, 14.0f);
        tvOkView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        tvOkView.setTextColor(Theme.getColor(Theme.key_actionBarDefaultTitle));
        tvOkView.setGravity(16);
        menu.addItemView(1, tvOkView);
    }

    private void initView() {
        this.mTvAddGroup.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.mTvAddGroup.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
        Drawable[] ds = this.mTvAddGroup.getCompoundDrawables();
        if (ds[0] != null) {
            ds[0].setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteBlueButton), PorterDuff.Mode.SRC_IN));
            this.mTvAddGroup.setCompoundDrawables(ds[0], ds[1], ds[2], ds[3]);
        }
        initList();
    }

    private void initList() {
        this.mRcvList.setLayoutManager(new LinearLayoutManager(getParentActivity()));
        RecyclerListView recyclerListView = this.mRcvList;
        GroupManageAdapter groupManageAdapter = new GroupManageAdapter(getParentActivity());
        this.mAdapter = groupManageAdapter;
        recyclerListView.setAdapter(groupManageAdapter);
        ItemTouchHelper itemTouchHelper = new ItemTouchHelper(new TouchHelperCallback());
        itemTouchHelper.attachToRecyclerView(this.mRcvList);
    }

    @OnClick({R.attr.tv_add_group})
    public void onViewClicked() {
        presentFragment(new CreateGroupingActivity());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showSaveDialog() {
        WalletDialog dialog = new WalletDialog(getParentActivity());
        dialog.setMessage(LocaleController.getString("SaveGroupingChangeTips", R.string.SaveGroupingChangeTips));
        dialog.setPositiveButton(LocaleController.getString("Save", R.string.Save), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$GroupingMgrActivity$59vXOWxyWwA5vdugVKkEfNVfRhE
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showSaveDialog$0$GroupingMgrActivity(dialogInterface, i);
            }
        });
        dialog.setNegativeButton(LocaleController.getString("NotSave", R.string.NotSave), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$GroupingMgrActivity$BWsBt76azPFp2ArSV1BRZUCberI
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$showSaveDialog$1$GroupingMgrActivity(dialogInterface, i);
            }
        });
        showDialog(dialog);
    }

    public /* synthetic */ void lambda$showSaveDialog$0$GroupingMgrActivity(DialogInterface dialogInterface, int i) {
        saveChanged();
    }

    public /* synthetic */ void lambda$showSaveDialog$1$GroupingMgrActivity(DialogInterface dialogInterface, int i) {
        finishFragment();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void saveChanged() {
        this.requestCount = 0;
        this.requestDoneCount = 0;
        if (isOrderChanged()) {
            saveOrderChange();
            this.requestCount++;
        }
        if (!this.deletedGroupIds.isEmpty()) {
            saveDeleteChange();
            this.requestCount++;
        }
    }

    private void saveOrderChange() {
        final AlertDialog alertDialog = new AlertDialog(getParentActivity(), 3);
        TLRPCContacts.TL_changeGroupOrder req = new TLRPCContacts.TL_changeGroupOrder();
        for (int i = 0; i < this.genres.size(); i++) {
            TLRPCContacts.TL_contactGroupOrderInfo orderInfo = new TLRPCContacts.TL_contactGroupOrderInfo();
            orderInfo.group_id = this.genres.get(i).getGroupId();
            orderInfo.order_id = i;
            req.group_orders.add(orderInfo);
        }
        final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$GroupingMgrActivity$wyJbzBQ7auH-P5EYtmsG3DEZ9So
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$saveOrderChange$3$GroupingMgrActivity(alertDialog, tLObject, tL_error);
            }
        });
        getConnectionsManager().bindRequestToGuid(reqId, this.classGuid);
        alertDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$GroupingMgrActivity$3jRBBgqh53nwxUV1I0b39fSYRcc
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                this.f$0.lambda$saveOrderChange$4$GroupingMgrActivity(reqId, dialogInterface);
            }
        });
        showDialog(alertDialog);
    }

    public /* synthetic */ void lambda$saveOrderChange$3$GroupingMgrActivity(final AlertDialog alertDialog, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$GroupingMgrActivity$tXCTc4Dw13ww0aDhlyAQvAcBDX8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$2$GroupingMgrActivity(alertDialog, error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$2$GroupingMgrActivity(AlertDialog alertDialog, TLRPC.TL_error error, TLObject response) {
        alertDialog.dismiss();
        this.requestDoneCount++;
        if (error == null) {
            if (response instanceof TLRPC.TL_boolTrue) {
                this.defaultOrders.clear();
                for (Genre genre : this.genres) {
                    this.defaultOrders.add(Integer.valueOf(genre.getOrderId()));
                }
                if (this.requestDoneCount == this.requestCount) {
                    finishFragment();
                    return;
                }
                return;
            }
            ToastUtils.show((CharSequence) "修改分组顺序失败，请稍后重试");
            return;
        }
        ToastUtils.show((CharSequence) error.text);
    }

    public /* synthetic */ void lambda$saveOrderChange$4$GroupingMgrActivity(int reqId, DialogInterface dialog1) {
        getConnectionsManager().cancelRequest(reqId, true);
        this.requestCount--;
    }

    private void saveDeleteChange() {
        final AlertDialog alertDialog = new AlertDialog(getParentActivity(), 3);
        TLRPCContacts.TL_deleteGroups req = new TLRPCContacts.TL_deleteGroups();
        req.group_ids.addAll(this.deletedGroupIds);
        final int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$GroupingMgrActivity$tCg7v--a7Pn1DI6SYthqAWlkbrM
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$saveDeleteChange$6$GroupingMgrActivity(alertDialog, tLObject, tL_error);
            }
        });
        getConnectionsManager().bindRequestToGuid(reqId, this.classGuid);
        alertDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$GroupingMgrActivity$UehVI6N5wIkT4tTtcIPYx5tto1s
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                this.f$0.lambda$saveDeleteChange$7$GroupingMgrActivity(reqId, dialogInterface);
            }
        });
        showDialog(alertDialog);
    }

    public /* synthetic */ void lambda$saveDeleteChange$6$GroupingMgrActivity(final AlertDialog alertDialog, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$GroupingMgrActivity$jHnuf7NtwGgsnGT0AMgZU4UCioY
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$5$GroupingMgrActivity(alertDialog, error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$5$GroupingMgrActivity(AlertDialog alertDialog, TLRPC.TL_error error, TLObject response) {
        alertDialog.dismiss();
        this.requestDoneCount++;
        if (error == null) {
            if (response instanceof TLRPC.TL_boolTrue) {
                this.deletedGroupIds.clear();
                if (this.requestDoneCount == this.requestCount) {
                    finishFragment();
                    return;
                }
                return;
            }
            ToastUtils.show((CharSequence) "删除分组失败，请稍后重试");
            return;
        }
        ToastUtils.show((CharSequence) error.text);
    }

    public /* synthetic */ void lambda$saveDeleteChange$7$GroupingMgrActivity(int reqId, DialogInterface dialog1) {
        getConnectionsManager().cancelRequest(reqId, true);
        this.requestCount--;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean isOrderChanged() {
        List<Integer> newOrders = new ArrayList<>();
        for (Genre genre : this.genres) {
            newOrders.add(Integer.valueOf(genre.getOrderId()));
        }
        if (!newOrders.equals(this.defaultOrders)) {
            return true;
        }
        return false;
    }

    public class TouchHelperCallback extends ItemTouchHelper.Callback {
        public TouchHelperCallback() {
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public boolean isLongPressDragEnabled() {
            return true;
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public int getMovementFlags(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder) {
            return makeMovementFlags(3, 0);
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public boolean onMove(RecyclerView recyclerView, RecyclerView.ViewHolder source, RecyclerView.ViewHolder target) {
            GroupingMgrActivity.this.mAdapter.swapElements(source.getAdapterPosition(), target.getAdapterPosition());
            return true;
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public void onChildDraw(Canvas c, RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder, float dX, float dY, int actionState, boolean isCurrentlyActive) {
            super.onChildDraw(c, recyclerView, viewHolder, dX, dY, actionState, isCurrentlyActive);
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public void onSelectedChanged(RecyclerView.ViewHolder viewHolder, int actionState) {
            if (actionState != 0) {
                GroupingMgrActivity.this.mRcvList.cancelClickRunnables(false);
                viewHolder.itemView.setPressed(true);
            }
            super.onSelectedChanged(viewHolder, actionState);
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public void onSwiped(RecyclerView.ViewHolder viewHolder, int direction) {
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public void clearView(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder) {
            super.clearView(recyclerView, viewHolder);
            viewHolder.itemView.setPressed(false);
        }
    }

    public class GroupManageAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public GroupManageAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            SwipeLayout swipeLayout = new SwipeLayout(this.mContext) { // from class: im.uwrkaxlmjj.ui.hui.contacts.GroupingMgrActivity.GroupManageAdapter.1
                @Override // android.view.View
                public boolean onTouchEvent(MotionEvent event) {
                    if (isExpanded()) {
                        return true;
                    }
                    return super.onTouchEvent(event);
                }
            };
            View view = LayoutInflater.from(this.mContext).inflate(R.layout.item_group_manage, parent, false);
            swipeLayout.setUpView(view);
            return new RecyclerListView.Holder(swipeLayout);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            String[] rightTexts;
            int[] rightColors;
            int[] rightColors2;
            SwipeLayout swipeLayout = (SwipeLayout) holder.itemView;
            swipeLayout.setItemWidth(AndroidUtilities.dp(75.0f));
            View content = swipeLayout.getMainLayout();
            MryTextView tvGroupName = (MryTextView) content.findViewById(R.attr.tv_group_name);
            MryTextView tvMemberNumber = (MryTextView) content.findViewById(R.attr.tv_member_number);
            MryDividerCell divider = (MryDividerCell) content.findViewById(R.attr.divider);
            final Genre genre = (Genre) GroupingMgrActivity.this.genres.get(position);
            tvGroupName.setText(genre.getTitle());
            tvMemberNumber.setText(genre.getOnlineCount() + "/" + genre.getItemCount());
            if (getItemCount() == 1) {
                content.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                divider.setVisibility(8);
            } else if (position == 0) {
                content.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                divider.setVisibility(0);
            } else if (position == getItemCount() - 1) {
                content.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                divider.setVisibility(8);
            } else {
                content.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                divider.setVisibility(0);
            }
            if (genre.getGroupId() == 0) {
                rightColors2 = new int[]{-3881788};
                rightTexts = new String[]{LocaleController.getString(R.string.Rename)};
                rightColors = new int[]{-1};
            } else {
                int[] rightColors3 = {-3881788, -12862209, -570319};
                rightTexts = new String[]{LocaleController.getString(R.string.Rename), LocaleController.getString(R.string.GroupAddMembers), LocaleController.getString(R.string.Delete)};
                rightColors = new int[]{-1, -1, -1};
                rightColors2 = rightColors3;
            }
            swipeLayout.setRightTexts(rightTexts);
            swipeLayout.setRightTextColors(rightColors);
            swipeLayout.setRightColors(rightColors2);
            swipeLayout.setTextSize(AndroidUtilities.sp2px(13.0f));
            swipeLayout.rebuildLayout();
            swipeLayout.setOnSwipeItemClickListener(new SwipeLayout.OnSwipeItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$GroupingMgrActivity$GroupManageAdapter$8Mi3tzQ-POtCc7dYgZZSVpynCU0
                @Override // im.uwrkaxlmjj.ui.hviews.slidemenu.SwipeLayout.OnSwipeItemClickListener
                public final void onSwipeItemClick(boolean z, int i) {
                    this.f$0.lambda$onBindViewHolder$10$GroupingMgrActivity$GroupManageAdapter(genre, z, i);
                }
            });
        }

        public /* synthetic */ void lambda$onBindViewHolder$10$GroupingMgrActivity$GroupManageAdapter(final Genre genre, boolean left, int index) {
            if (!left) {
                if (index != 0) {
                    if (index == 1) {
                        final List<TLRPC.User> users = new ArrayList<>();
                        for (Artist artist : genre.getItems()) {
                            TLRPC.User user = GroupingMgrActivity.this.getMessagesController().getUser(Integer.valueOf(artist.getUserId()));
                            if (user != null) {
                                users.add(user);
                            }
                        }
                        AddGroupingUserActivity fragment = new AddGroupingUserActivity(users, 2);
                        fragment.setDelegate(new AddGroupingUserActivity.AddGroupingUserActivityDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$GroupingMgrActivity$GroupManageAdapter$ibnEtYW0oylkki7Sv1KqJz7py-s
                            @Override // im.uwrkaxlmjj.ui.hui.contacts.AddGroupingUserActivity.AddGroupingUserActivityDelegate
                            public final void didSelectedContact(ArrayList arrayList) {
                                this.f$0.lambda$null$9$GroupingMgrActivity$GroupManageAdapter(users, genre, arrayList);
                            }
                        });
                        GroupingMgrActivity.this.presentFragment(fragment);
                        return;
                    }
                    if (index == 2 && genre.getGroupId() != 0) {
                        GroupingMgrActivity.this.defaultOrders.remove(Integer.valueOf(genre.getOrderId()));
                        GroupingMgrActivity.this.deletedGroupIds.add(Integer.valueOf(genre.getGroupId()));
                        GroupingMgrActivity.this.genres.remove(genre);
                        notifyDataSetChanged();
                        return;
                    }
                    return;
                }
                final Dialog dialog = new Dialog(GroupingMgrActivity.this.getParentActivity());
                GroupingMgrActivity.this.showDialog(dialog);
                View view = LayoutInflater.from(GroupingMgrActivity.this.getParentActivity()).inflate(R.layout.dialog_rename_grouping_layout, (ViewGroup) null);
                view.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$GroupingMgrActivity$GroupManageAdapter$P_aJkwlcmEVL15mdegipygWytwg
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view2) {
                        dialog.dismiss();
                    }
                });
                Window window = dialog.getWindow();
                window.setBackgroundDrawable(new ColorDrawable());
                WindowManager wm = GroupingMgrActivity.this.getParentActivity().getWindowManager();
                Display display = wm.getDefaultDisplay();
                WindowManager.LayoutParams lp = window.getAttributes();
                lp.width = display.getWidth();
                lp.height = display.getHeight();
                window.setAttributes(lp);
                window.setContentView(view);
                final LinearLayout llNotSupportEmojiTips = (LinearLayout) view.findViewById(R.attr.ll_not_support_emoji_tips);
                LinearLayout llContainer = (LinearLayout) view.findViewById(R.attr.ll_container);
                final MryEditText etGroupingName = (MryEditText) view.findViewById(R.attr.et_grouping_name);
                MryTextView tvNotSave = (MryTextView) view.findViewById(R.attr.tv_not_save);
                final MryTextView tvSave = (MryTextView) view.findViewById(R.attr.tv_save);
                llNotSupportEmojiTips.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                llContainer.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(10.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                tvNotSave.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText));
                tvSave.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
                etGroupingName.setText(genre.getTitle());
                etGroupingName.setFilters(new InputFilter[]{GroupingMgrActivity.this.new LengthFilter(28)});
                etGroupingName.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.hui.contacts.GroupingMgrActivity.GroupManageAdapter.2
                    @Override // android.text.TextWatcher
                    public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                    }

                    @Override // android.text.TextWatcher
                    public void onTextChanged(CharSequence s, int start, int before, int count) {
                        boolean hasEmoji = false;
                        for (int i = 0; i < s.length(); i++) {
                            int type = Character.getType(s.charAt(i));
                            if (type == 19 || type == 28) {
                                hasEmoji = true;
                                break;
                            }
                        }
                        boolean z = false;
                        llNotSupportEmojiTips.setVisibility(hasEmoji ? 0 : 8);
                        MryTextView mryTextView = tvSave;
                        if (!hasEmoji && !TextUtils.isEmpty(s)) {
                            z = true;
                        }
                        mryTextView.setEnabled(z);
                    }

                    @Override // android.text.TextWatcher
                    public void afterTextChanged(Editable s) {
                    }
                });
                tvNotSave.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$GroupingMgrActivity$GroupManageAdapter$V9WxZKTxZkw6SsSBOR_sBKzn23o
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view2) {
                        dialog.dismiss();
                    }
                });
                tvSave.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$GroupingMgrActivity$GroupManageAdapter$WXeyOw1rWH5OHSbIMkd9g6buC3Y
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$null$5$GroupingMgrActivity$GroupManageAdapter(dialog, genre, etGroupingName, view2);
                    }
                });
            }
        }

        public /* synthetic */ void lambda$null$5$GroupingMgrActivity$GroupManageAdapter(Dialog dialog, Genre genre, MryEditText etGroupingName, View v) {
            dialog.dismiss();
            final AlertDialog alertDialog = new AlertDialog(GroupingMgrActivity.this.getParentActivity(), 3);
            TLRPCContacts.TL_changeGroupName req = new TLRPCContacts.TL_changeGroupName();
            req.group_id = genre.getGroupId();
            req.title = etGroupingName.getText().toString();
            final int reqId = GroupingMgrActivity.this.getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$GroupingMgrActivity$GroupManageAdapter$3Y-NbUdtX_SE9RL8b9NNesVUFpo
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$GroupingMgrActivity$GroupManageAdapter$Z7-XgY1u00uSBBC44d39UTCeKds
                        @Override // java.lang.Runnable
                        public final void run() {
                            GroupingMgrActivity.GroupManageAdapter.lambda$null$2(alertDialog, tL_error, tLObject);
                        }
                    });
                }
            });
            GroupingMgrActivity.this.getConnectionsManager().bindRequestToGuid(reqId, GroupingMgrActivity.this.classGuid);
            alertDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$GroupingMgrActivity$GroupManageAdapter$QvoeL2C2mik-S4He9DM-nwv5JyM
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    this.f$0.lambda$null$4$GroupingMgrActivity$GroupManageAdapter(reqId, dialogInterface);
                }
            });
            GroupingMgrActivity.this.showDialog(alertDialog);
        }

        static /* synthetic */ void lambda$null$2(AlertDialog alertDialog, TLRPC.TL_error error, TLObject response) {
            alertDialog.dismiss();
            if (error == null) {
                if (!(response instanceof TLRPC.TL_boolTrue)) {
                    ToastUtils.show((CharSequence) "重命名失败，请稍后重试");
                    return;
                }
                return;
            }
            ToastUtils.show((CharSequence) error.text);
        }

        public /* synthetic */ void lambda$null$4$GroupingMgrActivity$GroupManageAdapter(int reqId, DialogInterface dialog1) {
            GroupingMgrActivity.this.getConnectionsManager().cancelRequest(reqId, true);
        }

        public /* synthetic */ void lambda$null$9$GroupingMgrActivity$GroupManageAdapter(List users, Genre genre, ArrayList users1) {
            if (users.equals(users1)) {
                return;
            }
            final AlertDialog alertDialog = new AlertDialog(GroupingMgrActivity.this.getParentActivity(), 3);
            TLRPCContacts.TL_setUserGroup req = new TLRPCContacts.TL_setUserGroup();
            req.group_id = genre.getGroupId();
            Iterator it = users1.iterator();
            while (it.hasNext()) {
                TLRPC.User user = (TLRPC.User) it.next();
                TLRPCContacts.TL_inputPeerUserChange inputPeer = new TLRPCContacts.TL_inputPeerUserChange();
                inputPeer.access_hash = user.access_hash;
                inputPeer.user_id = user.id;
                inputPeer.fist_name = user.first_name;
                req.users.add(inputPeer);
            }
            final int reqId = GroupingMgrActivity.this.getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$GroupingMgrActivity$GroupManageAdapter$NHGWHYEFo-IA452EVfx1UK48FAw
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$GroupingMgrActivity$GroupManageAdapter$zbjHYrTnaT7nfEvbAS2y179KpLg
                        @Override // java.lang.Runnable
                        public final void run() {
                            GroupingMgrActivity.GroupManageAdapter.lambda$null$6(alertDialog, tL_error, tLObject);
                        }
                    });
                }
            });
            GroupingMgrActivity.this.getConnectionsManager().bindRequestToGuid(reqId, GroupingMgrActivity.this.classGuid);
            alertDialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$GroupingMgrActivity$GroupManageAdapter$Z_SILIYSNRnRVlt27fYCKXo3fbk
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    this.f$0.lambda$null$8$GroupingMgrActivity$GroupManageAdapter(reqId, dialogInterface);
                }
            });
            GroupingMgrActivity.this.showDialog(alertDialog);
        }

        static /* synthetic */ void lambda$null$6(AlertDialog alertDialog, TLRPC.TL_error error, TLObject response) {
            alertDialog.dismiss();
            if (error == null) {
                if (response instanceof TLRPC.TL_boolTrue) {
                    ToastUtils.show((CharSequence) "添加成功");
                    return;
                } else {
                    ToastUtils.show((CharSequence) "添加失败，请稍后重试");
                    return;
                }
            }
            ToastUtils.show((CharSequence) error.text);
        }

        public /* synthetic */ void lambda$null$8$GroupingMgrActivity$GroupManageAdapter(int reqId, DialogInterface dialog1) {
            GroupingMgrActivity.this.getConnectionsManager().cancelRequest(reqId, true);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return GroupingMgrActivity.this.genres.size();
        }

        public void swapElements(int fromIndex, int toIndex) {
            Genre from = (Genre) GroupingMgrActivity.this.genres.get(fromIndex);
            Genre to = (Genre) GroupingMgrActivity.this.genres.get(toIndex);
            GroupingMgrActivity.this.genres.set(fromIndex, to);
            GroupingMgrActivity.this.genres.set(toIndex, from);
            notifyItemMoved(fromIndex, toIndex);
            notifyItemRangeChanged(Math.min(fromIndex, toIndex), Math.abs(fromIndex - toIndex) + 1);
        }
    }

    private class LengthFilter implements InputFilter {
        private int maxLen;

        public LengthFilter(int maxLen) {
            this.maxLen = maxLen;
        }

        @Override // android.text.InputFilter
        public CharSequence filter(CharSequence source, int start, int end, Spanned dest, int dstart, int dend) {
            int dindex = 0;
            int count = 0;
            while (count <= this.maxLen && dindex < dest.length()) {
                int dindex2 = dindex + 1;
                char c = dest.charAt(dindex);
                if (c < 128) {
                    count++;
                } else {
                    count += 2;
                }
                dindex = dindex2;
            }
            int dindex3 = this.maxLen;
            if (count > dindex3) {
                return dest.subSequence(0, dindex - 1);
            }
            int sindex = 0;
            while (count <= this.maxLen && sindex < source.length()) {
                int sindex2 = sindex + 1;
                char c2 = source.charAt(sindex);
                if (c2 < 128) {
                    count++;
                } else {
                    count += 2;
                }
                sindex = sindex2;
            }
            if (count > this.maxLen) {
                sindex--;
            }
            return source.subSequence(0, sindex);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        if (isOrderChanged() || !this.deletedGroupIds.isEmpty()) {
            showSaveDialog();
            return false;
        }
        return super.onBackPressed();
    }
}
