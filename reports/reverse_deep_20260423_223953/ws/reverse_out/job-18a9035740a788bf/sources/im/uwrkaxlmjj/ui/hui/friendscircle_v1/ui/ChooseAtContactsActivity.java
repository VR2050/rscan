package im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Property;
import android.view.View;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.adapters.SearchAdapter;
import im.uwrkaxlmjj.ui.cells.GraySectionCell;
import im.uwrkaxlmjj.ui.cells.LetterSectionCell;
import im.uwrkaxlmjj.ui.cells.ProfileSearchCell;
import im.uwrkaxlmjj.ui.cells.TextCell;
import im.uwrkaxlmjj.ui.cells.UserCell;
import im.uwrkaxlmjj.ui.components.EmptyTextProgressView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.decoration.StickyDecoration;
import im.uwrkaxlmjj.ui.decoration.listener.GroupListener;
import im.uwrkaxlmjj.ui.hui.adapter.CreateSecureAdapter;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FCIndexBar;
import im.uwrkaxlmjj.ui.hviews.search.MrySearchView;
import java.util.ArrayList;
import java.util.Set;
import java.util.TreeSet;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ChooseAtContactsActivity extends BaseSearchViewFragment implements NotificationCenter.NotificationCenterDelegate {
    private AccelerateDecelerateInterpolator accelerateDecelerateInterpolator;
    private boolean allowBots;
    private boolean allowUsernameSearch;
    private boolean askAboutContacts;
    private boolean checkPermission;
    private boolean creatingChat;
    private ContactsActivityDelegate delegate;
    private EmptyTextProgressView emptyView;
    private LinearLayoutManager layoutManager;
    private RecyclerListView listView;
    private CreateSecureAdapter listViewAdapter;
    private AlertDialog permissionDialog;
    private SearchAdapter searchListViewAdapter;
    private boolean searchWas;
    private boolean searching;
    private AnimatorSet set;
    private FCIndexBar sideBar;

    public interface ContactsActivityDelegate {
        void didSelectContact(TLRPC.User user);
    }

    public ChooseAtContactsActivity(Bundle args) {
        super(args);
        this.allowBots = true;
        this.allowUsernameSearch = true;
        this.askAboutContacts = true;
        this.checkPermission = true;
        this.accelerateDecelerateInterpolator = new AccelerateDecelerateInterpolator();
        this.set = null;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.contactsDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.updateInterfaces);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.closeChats);
        this.checkPermission = UserConfig.getInstance(this.currentAccount).syncContacts;
        ContactsController.getInstance(this.currentAccount).checkInviteText();
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.contactsDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.updateInterfaces);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.closeChats);
        this.delegate = null;
        AnimatorSet animatorSet = this.set;
        if (animatorSet != null && animatorSet.isStarted()) {
            this.set.cancel();
            this.set.end();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.searching = false;
        this.searchWas = false;
        initActionBar();
        this.fragmentView = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ChooseAtContactsActivity.1
            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                super.onLayout(changed, left, top, right, bottom);
                if (ChooseAtContactsActivity.this.listView.getAdapter() == ChooseAtContactsActivity.this.listViewAdapter) {
                    if (ChooseAtContactsActivity.this.emptyView.getVisibility() == 0) {
                        ChooseAtContactsActivity.this.emptyView.setTranslationY(AndroidUtilities.dp(74.0f));
                        return;
                    }
                    return;
                }
                ChooseAtContactsActivity.this.emptyView.setTranslationY(AndroidUtilities.dp(0.0f));
            }
        };
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        super.createView(context);
        initList(frameLayout, context);
        initSideBar(frameLayout, context);
        return this.fragmentView;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment
    protected MrySearchView getSearchView() {
        this.searchView = new MrySearchView(getParentActivity());
        ((FrameLayout) this.fragmentView).addView(this.searchView, LayoutHelper.createFrame(-1, 46.0f));
        return this.searchView;
    }

    protected RecyclerListView getListView() {
        return this.listView;
    }

    private void initActionBar() {
        this.actionBar.setAllowOverlayTitle(false);
        this.actionBar.setCastShadows(false);
        this.actionBar.setTitle(LocaleController.getString("ChooseAtContacts", R.string.ChooseAtContacts));
        this.actionBar.setBackTitle(LocaleController.getString("Cancel", R.string.Cancel));
        this.actionBar.getBackTitleTextView().setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ChooseAtContactsActivity$UB1b3LmuRG3h_oZrkSpW_tFlogQ
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initActionBar$0$ChooseAtContactsActivity(view);
            }
        });
    }

    public /* synthetic */ void lambda$initActionBar$0$ChooseAtContactsActivity(View v) {
        finishFragment();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment
    protected void initSearchView() {
        super.initSearchView();
        this.searchView.setHintText(LocaleController.getString("Search", R.string.Search));
    }

    private void initList(FrameLayout frameLayout, Context context) {
        EmptyTextProgressView emptyTextProgressView = new EmptyTextProgressView(context);
        this.emptyView = emptyTextProgressView;
        emptyTextProgressView.setShowAtCenter(true);
        this.emptyView.setText(LocaleController.getString("NoContacts", R.string.NoContacts));
        this.emptyView.showTextView();
        frameLayout.addView(this.emptyView, LayoutHelper.createFrameSearchWithoutActionBar(-1, -1));
        this.searchListViewAdapter = new SearchAdapter(context, null, this.allowUsernameSearch, false, false, this.allowBots, true, 0);
        CreateSecureAdapter createSecureAdapter = new CreateSecureAdapter(context) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ChooseAtContactsActivity.2
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
            public void notifyDataSetChanged() {
                super.notifyDataSetChanged();
                if (ChooseAtContactsActivity.this.listView != null && ChooseAtContactsActivity.this.listView.getAdapter() == this) {
                    int count = super.getItemCount();
                    ChooseAtContactsActivity.this.emptyView.setVisibility(count == 0 ? 0 : 8);
                    if (ChooseAtContactsActivity.this.listViewAdapter.getItemCount() > 0) {
                        Set<String> letters = new TreeSet<>();
                        for (int i = 0; i < count; i++) {
                            String letter = ChooseAtContactsActivity.this.listViewAdapter.getLetter(i);
                            if (!TextUtils.isEmpty(letter)) {
                                letters.add(letter);
                            }
                        }
                        int i2 = letters.size();
                        if (i2 > 0) {
                            String[] strings = new String[letters.size()];
                            letters.toArray(strings);
                            ChooseAtContactsActivity.this.sideBar.setChars(strings);
                        }
                    }
                }
            }
        };
        this.listViewAdapter = createSecureAdapter;
        createSecureAdapter.setDisableSections(true);
        RecyclerListView recyclerListView = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ChooseAtContactsActivity.3
            @Override // android.view.View
            public void setPadding(int left, int top, int right, int bottom) {
                super.setPadding(left, top, right, bottom);
                if (ChooseAtContactsActivity.this.emptyView != null) {
                    ChooseAtContactsActivity.this.emptyView.setPadding(left, top, right, bottom);
                }
            }
        };
        this.listView = recyclerListView;
        recyclerListView.setVerticalScrollBarEnabled(false);
        RecyclerListView recyclerListView2 = this.listView;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context, 1, false);
        this.layoutManager = linearLayoutManager;
        recyclerListView2.setLayoutManager(linearLayoutManager);
        StickyDecoration.Builder decorationBuilder = StickyDecoration.Builder.init(new GroupListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ChooseAtContactsActivity$ygDv4bu6DtAPovDp2xLWhet8PGw
            @Override // im.uwrkaxlmjj.ui.decoration.listener.GroupListener
            public final String getGroupName(int i) {
                return this.f$0.lambda$initList$1$ChooseAtContactsActivity(i);
            }
        }).setGroupBackground(Theme.getColor(Theme.key_windowBackgroundGray)).setGroupTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText)).setGroupTextTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf")).setGroupHeight(AndroidUtilities.dp(24.0f)).setDivideColor(Color.parseColor("#EE96BC")).setGroupTextSize(AndroidUtilities.dp(14.0f)).setTextSideMargin(AndroidUtilities.dp(15.0f));
        StickyDecoration decoration = decorationBuilder.build();
        this.listView.addItemDecoration(decoration);
        this.listView.setAdapter(this.listViewAdapter);
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1, 0, AndroidUtilities.dp(46.0f), 0, 0));
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ChooseAtContactsActivity$6CkKA-uAcfs2wYWHz2NY4tenIs0
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initList$2$ChooseAtContactsActivity(view, i);
            }
        });
        this.listView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ChooseAtContactsActivity.4
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                if (newState == 1 && ChooseAtContactsActivity.this.searching && ChooseAtContactsActivity.this.searchWas) {
                    AndroidUtilities.hideKeyboard(ChooseAtContactsActivity.this.getParentActivity().getCurrentFocus());
                }
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                super.onScrolled(recyclerView, dx, dy);
            }
        });
    }

    public /* synthetic */ String lambda$initList$1$ChooseAtContactsActivity(int position) {
        if (this.listViewAdapter.getItemCount() > position && position > -1) {
            String letter = this.listViewAdapter.getLetter(position);
            return letter;
        }
        return null;
    }

    public /* synthetic */ void lambda$initList$2$ChooseAtContactsActivity(View view, int position) {
        TLRPC.User user;
        if (this.searching && this.searchWas) {
            Object object = this.searchListViewAdapter.getItem(position);
            if (!(object instanceof TLRPC.User) || (user = (TLRPC.User) object) == null) {
                return;
            }
            if (this.searchListViewAdapter.isGlobalSearch(position)) {
                ArrayList<TLRPC.User> users = new ArrayList<>();
                users.add(user);
                MessagesController.getInstance(this.currentAccount).putUsers(users, false);
                MessagesStorage.getInstance(this.currentAccount).putUsersAndChats(users, null, false, true);
            }
            if (user.id == UserConfig.getInstance(this.currentAccount).getClientUserId()) {
                return;
            }
            if (this.searchView != null && this.searchView.isSearchFieldVisible()) {
                this.searchView.closeSearchField();
            }
            this.creatingChat = true;
            ContactsActivityDelegate contactsActivityDelegate = this.delegate;
            if (contactsActivityDelegate != null) {
                contactsActivityDelegate.didSelectContact(user);
                finishFragment();
                return;
            }
            return;
        }
        int section = this.listViewAdapter.getSectionForPosition(position);
        int row = this.listViewAdapter.getPositionInSectionForPosition(position);
        if (row < 0 || section < 0) {
            return;
        }
        Object item1 = this.listViewAdapter.getItem(section, row);
        if (item1 instanceof TLRPC.User) {
            TLRPC.User user2 = (TLRPC.User) item1;
            this.creatingChat = true;
            ContactsActivityDelegate contactsActivityDelegate2 = this.delegate;
            if (contactsActivityDelegate2 != null) {
                contactsActivityDelegate2.didSelectContact(user2);
                finishFragment();
            }
        }
    }

    private void initSideBar(FrameLayout frameLayout, Context context) {
        TextView textView = new TextView(context);
        textView.setTextSize(50.0f);
        textView.setGravity(17);
        textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        frameLayout.addView(textView, LayoutHelper.createFrame(100, 100, 17));
        FCIndexBar fCIndexBar = new FCIndexBar(context);
        this.sideBar = fCIndexBar;
        fCIndexBar.setTextView(textView);
        frameLayout.addView(this.sideBar, LayoutHelper.createFrame(35.0f, -2.0f, 21, 0.0f, 45.0f, 0.0f, 45.0f));
        this.sideBar.setOnTouchingLetterChangedListener(new FCIndexBar.OnTouchingLetterChangedListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ChooseAtContactsActivity$0YtdACsxKI7kGgIo3IW4fBXQSoM
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FCIndexBar.OnTouchingLetterChangedListener
            public final void onTouchingLetterChanged(String str) {
                this.f$0.lambda$initSideBar$3$ChooseAtContactsActivity(str);
            }
        });
    }

    public /* synthetic */ void lambda$initSideBar$3$ChooseAtContactsActivity(String s) {
        int section = this.listViewAdapter.getSectionForChar(s.charAt(0));
        int position = this.listViewAdapter.getPositionForSection(section);
        if (position != -1) {
            this.listView.getLayoutManager().scrollToPosition(position);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        CreateSecureAdapter createSecureAdapter = this.listViewAdapter;
        if (createSecureAdapter != null) {
            createSecureAdapter.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        if (this.searchView != null && this.searchView.isSearchFieldVisible()) {
            this.searchView.closeSearchField();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected AnimatorSet onCustomTransitionAnimation(boolean isOpen, final Runnable callback) {
        int parentHeight = this.parentLayout.getMeasuredHeight();
        int actionBarHeight = this.actionBar.getMeasuredHeight();
        AnimatorSet animatorSet = this.set;
        if (animatorSet != null && animatorSet.isStarted()) {
            this.set.cancel();
        }
        AnimatorSet animatorSet2 = new AnimatorSet();
        this.set = animatorSet2;
        animatorSet2.setInterpolator(this.accelerateDecelerateInterpolator);
        this.set.setDuration(200L);
        if (isOpen) {
            this.set.playTogether(ObjectAnimator.ofFloat(this.actionBar, (Property<ActionBar, Float>) View.TRANSLATION_Y, parentHeight, 0.0f), ObjectAnimator.ofFloat(this.actionBar, (Property<ActionBar, Float>) View.ALPHA, 0.0f, 1.0f), ObjectAnimator.ofFloat(this.fragmentView, (Property<View, Float>) View.TRANSLATION_Y, parentHeight + actionBarHeight, 0.0f), ObjectAnimator.ofFloat(this.fragmentView, (Property<View, Float>) View.ALPHA, 0.0f, 1.0f));
        } else {
            this.set.playTogether(ObjectAnimator.ofFloat(this.actionBar, (Property<ActionBar, Float>) View.TRANSLATION_Y, 0.0f, parentHeight), ObjectAnimator.ofFloat(this.actionBar, (Property<ActionBar, Float>) View.ALPHA, 1.0f, 0.0f), ObjectAnimator.ofFloat(this.fragmentView, (Property<View, Float>) View.TRANSLATION_Y, 0.0f, parentHeight + actionBarHeight), ObjectAnimator.ofFloat(this.fragmentView, (Property<View, Float>) View.ALPHA, 1.0f, 0.0f));
        }
        this.set.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ChooseAtContactsActivity.5
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                Runnable runnable = callback;
                if (runnable != null) {
                    runnable.run();
                }
            }
        });
        this.set.start();
        return this.set;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onTransitionAnimationEnd(boolean isOpen, boolean backward) {
        super.onTransitionAnimationEnd(isOpen, backward);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        CreateSecureAdapter createSecureAdapter;
        if (id == NotificationCenter.contactsDidLoad) {
            CreateSecureAdapter createSecureAdapter2 = this.listViewAdapter;
            if (createSecureAdapter2 != null) {
                createSecureAdapter2.notifyDataSetChanged();
                return;
            }
            return;
        }
        if (id == NotificationCenter.updateInterfaces) {
            int mask = ((Integer) args[0]).intValue();
            if ((mask & 2) != 0 || (mask & 1) != 0 || (mask & 4) != 0) {
                updateVisibleRows(mask);
            }
            if ((mask & 4) != 0 && (createSecureAdapter = this.listViewAdapter) != null) {
                createSecureAdapter.sortOnlineContacts();
                return;
            }
            return;
        }
        if (id == NotificationCenter.closeChats && !this.creatingChat) {
            removeSelfFromStack();
        }
    }

    private void updateVisibleRows(int mask) {
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null) {
            int count = recyclerListView.getChildCount();
            for (int a = 0; a < count; a++) {
                View child = this.listView.getChildAt(a);
                if (child instanceof UserCell) {
                    ((UserCell) child).update(mask);
                }
            }
        }
    }

    public void setDelegate(ContactsActivityDelegate delegate) {
        this.delegate = delegate;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        ThemeDescription.ThemeDescriptionDelegate cellDelegate = new ThemeDescription.ThemeDescriptionDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$ChooseAtContactsActivity$IvITehYefDpYCuXST4pPZw2eH1w
            @Override // im.uwrkaxlmjj.ui.actionbar.ThemeDescription.ThemeDescriptionDelegate
            public final void didSetColor() {
                this.f$0.lambda$getThemeDescriptions$4$ChooseAtContactsActivity();
            }
        };
        return new ThemeDescription[]{new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCH, null, null, null, null, Theme.key_actionBarDefaultSearch), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCHPLACEHOLDER, null, null, null, null, Theme.key_actionBarDefaultSearchPlaceholder), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SECTIONS, new Class[]{LetterSectionCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.emptyView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_emptyListPlaceholder), new ThemeDescription(this.listView, ThemeDescription.FLAG_FASTSCROLL, null, null, null, null, Theme.key_fastScrollActive), new ThemeDescription(this.listView, ThemeDescription.FLAG_FASTSCROLL, null, null, null, null, Theme.key_fastScrollInactive), new ThemeDescription(this.listView, ThemeDescription.FLAG_FASTSCROLL, null, null, null, null, Theme.key_fastScrollText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, new String[]{"nameTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, new String[]{"statusColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteGrayText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, new String[]{"statusOnlineColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteBlueText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, null, new Drawable[]{Theme.avatar_savedDrawable}, null, Theme.key_avatar_text), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundRed), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundOrange), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundViolet), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundGreen), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundCyan), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundBlue), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundPink), new ThemeDescription(this.listView, ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_CHECKTAG, new Class[]{TextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_CHECKTAG, new Class[]{TextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueText2), new ThemeDescription(this.listView, 0, new Class[]{TextCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayIcon), new ThemeDescription(this.listView, 0, new Class[]{GraySectionCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_graySectionText), new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{GraySectionCell.class}, null, null, null, Theme.key_graySection), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, null, new Drawable[]{Theme.dialogs_groupDrawable, Theme.dialogs_broadcastDrawable, Theme.dialogs_botDrawable}, null, Theme.key_chats_nameIcon), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, null, new Drawable[]{Theme.dialogs_verifiedCheckDrawable}, null, Theme.key_chats_verifiedCheck), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, null, new Drawable[]{Theme.dialogs_verifiedDrawable}, null, Theme.key_chats_verifiedBackground), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, Theme.dialogs_offlinePaint, null, null, Theme.key_windowBackgroundWhiteGrayText3), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, Theme.dialogs_onlinePaint, null, null, Theme.key_windowBackgroundWhiteBlueText3), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, (String[]) null, new Paint[]{Theme.dialogs_namePaint, Theme.dialogs_searchNamePaint}, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_name), new ThemeDescription(this.listView, 0, new Class[]{ProfileSearchCell.class}, (String[]) null, new Paint[]{Theme.dialogs_nameEncryptedPaint, Theme.dialogs_searchNameEncryptedPaint}, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_secretName)};
    }

    public /* synthetic */ void lambda$getThemeDescriptions$4$ChooseAtContactsActivity() {
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null) {
            int count = recyclerListView.getChildCount();
            for (int a = 0; a < count; a++) {
                View child = this.listView.getChildAt(a);
                if (child instanceof UserCell) {
                    ((UserCell) child).update(0);
                } else if (child instanceof ProfileSearchCell) {
                    ((ProfileSearchCell) child).update(0);
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onSearchExpand() {
        this.searching = true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public boolean canCollapseSearch() {
        this.searchListViewAdapter.searchDialogs(null);
        this.searching = false;
        this.searchWas = false;
        this.listView.setAdapter(this.listViewAdapter);
        this.listViewAdapter.notifyDataSetChanged();
        this.listView.setVerticalScrollBarEnabled(false);
        this.listView.setEmptyView(null);
        this.emptyView.setText(LocaleController.getString("NoContacts", R.string.NoContacts));
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onSearchCollapse() {
        this.searching = false;
        this.searchWas = false;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onTextChange(String text) {
        if (this.searchListViewAdapter == null) {
            return;
        }
        if (text.length() != 0) {
            this.searchWas = true;
            RecyclerListView recyclerListView = this.listView;
            if (recyclerListView != null) {
                recyclerListView.setAdapter(this.searchListViewAdapter);
                this.searchListViewAdapter.notifyDataSetChanged();
                this.listView.setVerticalScrollBarEnabled(false);
            }
            EmptyTextProgressView emptyTextProgressView = this.emptyView;
            if (emptyTextProgressView != null) {
                this.listView.setEmptyView(emptyTextProgressView);
                this.emptyView.setText(LocaleController.getString("NoResult", R.string.NoResult));
            }
        }
        this.searchListViewAdapter.searchDialogs(text);
    }
}
