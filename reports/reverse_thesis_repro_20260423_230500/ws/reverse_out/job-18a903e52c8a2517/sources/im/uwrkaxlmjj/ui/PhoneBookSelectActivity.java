package im.uwrkaxlmjj.ui;

import android.content.Context;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.text.TextUtils;
import android.view.View;
import android.widget.EditText;
import android.widget.FrameLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.adapters.PhoneBookAdapter2;
import im.uwrkaxlmjj.ui.adapters.PhonebookSearchAdapter;
import im.uwrkaxlmjj.ui.cells.LetterSectionCell;
import im.uwrkaxlmjj.ui.cells.UserCell;
import im.uwrkaxlmjj.ui.components.EmptyTextProgressView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class PhoneBookSelectActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private static final int search_button = 0;
    private PhoneBookSelectActivityDelegate delegate;
    private EmptyTextProgressView emptyView;
    private RecyclerListView listView;
    private PhoneBookAdapter2 listViewAdapter;
    private ChatActivity parentFragment;
    private PhonebookSearchAdapter searchListViewAdapter;
    private boolean searchWas;
    private boolean searching;

    public interface PhoneBookSelectActivityDelegate {
        void didSelectContact(TLRPC.User user, boolean z, int i);
    }

    public PhoneBookSelectActivity(ChatActivity chatActivity) {
        this.parentFragment = chatActivity;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.contactsDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.closeChats);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.contactsDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.closeChats);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.searching = false;
        this.searchWas = false;
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setTitle(LocaleController.getString("SelectContact", R.string.SelectContact));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.PhoneBookSelectActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    PhoneBookSelectActivity.this.finishFragment();
                }
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        ActionBarMenuItem item = menu.addItem(0, R.drawable.ic_ab_search).setIsSearchField(true).setActionBarMenuItemSearchListener(new ActionBarMenuItem.ActionBarMenuItemSearchListener() { // from class: im.uwrkaxlmjj.ui.PhoneBookSelectActivity.2
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
            public void onSearchExpand() {
                PhoneBookSelectActivity.this.searching = true;
            }

            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
            public void onSearchCollapse() {
                PhoneBookSelectActivity.this.searchListViewAdapter.search(null);
                PhoneBookSelectActivity.this.searching = false;
                PhoneBookSelectActivity.this.searchWas = false;
                PhoneBookSelectActivity.this.listView.setAdapter(PhoneBookSelectActivity.this.listViewAdapter);
                PhoneBookSelectActivity.this.listView.setSectionsType(1);
                PhoneBookSelectActivity.this.listViewAdapter.notifyDataSetChanged();
                PhoneBookSelectActivity.this.listView.setFastScrollVisible(true);
                PhoneBookSelectActivity.this.listView.setVerticalScrollBarEnabled(false);
                PhoneBookSelectActivity.this.emptyView.setText(LocaleController.getString("NoContacts", R.string.NoContacts));
            }

            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem.ActionBarMenuItemSearchListener
            public void onTextChanged(EditText editText) {
                if (PhoneBookSelectActivity.this.searchListViewAdapter == null) {
                    return;
                }
                String text = ((Object) editText.getText()) + "";
                if (!TextUtils.isEmpty(text)) {
                    PhoneBookSelectActivity.this.searchWas = true;
                    PhoneBookSelectActivity.this.searchListViewAdapter.search(text);
                    return;
                }
                PhoneBookSelectActivity.this.searchWas = false;
                if (PhoneBookSelectActivity.this.listView != null && PhoneBookSelectActivity.this.listViewAdapter != null) {
                    PhoneBookSelectActivity.this.listView.setAdapter(PhoneBookSelectActivity.this.listViewAdapter);
                }
            }
        });
        item.setSearchFieldHint(LocaleController.getString("Search", R.string.Search));
        this.searchListViewAdapter = new PhonebookSearchAdapter(context) { // from class: im.uwrkaxlmjj.ui.PhoneBookSelectActivity.3
            @Override // im.uwrkaxlmjj.ui.adapters.PhonebookSearchAdapter
            protected void onUpdateSearchResults(String query) {
                if (!TextUtils.isEmpty(query) && PhoneBookSelectActivity.this.listView != null && PhoneBookSelectActivity.this.listView.getAdapter() != PhoneBookSelectActivity.this.searchListViewAdapter) {
                    PhoneBookSelectActivity.this.listView.setAdapter(PhoneBookSelectActivity.this.searchListViewAdapter);
                    PhoneBookSelectActivity.this.listView.setSectionsType(0);
                    PhoneBookSelectActivity.this.searchListViewAdapter.notifyDataSetChanged();
                    PhoneBookSelectActivity.this.listView.setFastScrollVisible(false);
                    PhoneBookSelectActivity.this.listView.setVerticalScrollBarEnabled(true);
                    PhoneBookSelectActivity.this.emptyView.setText(LocaleController.getString("NoResult", R.string.NoResult));
                }
            }
        };
        this.listViewAdapter = new PhoneBookAdapter2(context) { // from class: im.uwrkaxlmjj.ui.PhoneBookSelectActivity.4
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
            public void notifyDataSetChanged() {
                super.notifyDataSetChanged();
                if (PhoneBookSelectActivity.this.listView.getAdapter() == this) {
                    int count = super.getItemCount();
                    PhoneBookSelectActivity.this.listView.setFastScrollVisible(count != 0);
                }
            }
        };
        this.fragmentView = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.PhoneBookSelectActivity.5
            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                super.onLayout(changed, left, top, right, bottom);
                if (PhoneBookSelectActivity.this.listView.getAdapter() == PhoneBookSelectActivity.this.listViewAdapter) {
                    if (PhoneBookSelectActivity.this.emptyView.getVisibility() == 0) {
                        PhoneBookSelectActivity.this.emptyView.setTranslationY(AndroidUtilities.dp(74.0f));
                        return;
                    }
                    return;
                }
                PhoneBookSelectActivity.this.emptyView.setTranslationY(AndroidUtilities.dp(0.0f));
            }
        };
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        EmptyTextProgressView emptyTextProgressView = new EmptyTextProgressView(context);
        this.emptyView = emptyTextProgressView;
        emptyTextProgressView.setShowAtCenter(true);
        this.emptyView.setText(LocaleController.getString("NoContacts", R.string.NoContacts));
        this.emptyView.showTextView();
        frameLayout.addView(this.emptyView, LayoutHelper.createFrame(-1, -1.0f));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.setSectionsType(1);
        this.listView.setVerticalScrollBarEnabled(false);
        this.listView.setFastScrollEnabled();
        this.listView.setEmptyView(this.emptyView);
        this.listView.setLayoutManager(new LinearLayoutManager(context, 1, false));
        this.listView.setAdapter(this.listViewAdapter);
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1.0f));
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhoneBookSelectActivity$hQr2K4PnyMAqzKxwtG6oaDk14So
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$createView$1$PhoneBookSelectActivity(view, i);
            }
        });
        this.listView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.PhoneBookSelectActivity.6
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                if (newState == 1 && PhoneBookSelectActivity.this.searching && PhoneBookSelectActivity.this.searchWas) {
                    AndroidUtilities.hideKeyboard(PhoneBookSelectActivity.this.getParentActivity().getCurrentFocus());
                }
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                super.onScrolled(recyclerView, dx, dy);
            }
        });
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$createView$1$PhoneBookSelectActivity(View view, int position) {
        Object object;
        TLRPC.User user;
        ContactsController.Contact contact;
        String name;
        if (this.searching && this.searchWas) {
            object = this.searchListViewAdapter.getItem(position);
        } else {
            int section = this.listViewAdapter.getSectionForPosition(position);
            int row = this.listViewAdapter.getPositionInSectionForPosition(position);
            if (row < 0 || section < 0) {
                return;
            } else {
                object = this.listViewAdapter.getItem(section, row);
            }
        }
        if (object != null) {
            if (object instanceof ContactsController.Contact) {
                contact = (ContactsController.Contact) object;
                if (contact.user != null) {
                    name = ContactsController.formatName(contact.user.first_name, contact.user.last_name);
                } else {
                    name = "";
                }
            } else {
                if (object instanceof TLRPC.Contact) {
                    user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(((TLRPC.Contact) object).user_id));
                } else {
                    user = (TLRPC.User) object;
                }
                if (user == null) {
                    FileLog.e("ListView onItemClick user is null");
                    return;
                }
                ContactsController.Contact contact2 = new ContactsController.Contact();
                contact2.first_name = user.first_name;
                contact2.last_name = user.last_name;
                if (!TextUtils.isEmpty(user.phone)) {
                    contact2.phones.add(user.phone);
                } else {
                    contact2.phones.add("");
                }
                contact2.user = user;
                contact = contact2;
                name = ContactsController.formatName(contact2.first_name, contact2.last_name);
            }
            PhonebookShareActivity activity = new PhonebookShareActivity(contact, null, null, name);
            activity.setChatActivity(this.parentFragment);
            activity.setDelegate(new PhoneBookSelectActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhoneBookSelectActivity$OWe4n_ayhL5ToPVO9UzQ7Wdniyc
                @Override // im.uwrkaxlmjj.ui.PhoneBookSelectActivity.PhoneBookSelectActivityDelegate
                public final void didSelectContact(TLRPC.User user2, boolean z, int i) {
                    this.f$0.lambda$null$0$PhoneBookSelectActivity(user2, z, i);
                }
            });
            presentFragment(activity);
        }
    }

    public /* synthetic */ void lambda$null$0$PhoneBookSelectActivity(TLRPC.User user, boolean notify, int scheduleDate) {
        removeSelfFromStack();
        this.delegate.didSelectContact(user, notify, scheduleDate);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        PhoneBookAdapter2 phoneBookAdapter2 = this.listViewAdapter;
        if (phoneBookAdapter2 != null) {
            phoneBookAdapter2.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        if (this.actionBar != null) {
            this.actionBar.closeSearchField();
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.contactsDidLoad) {
            PhoneBookAdapter2 phoneBookAdapter2 = this.listViewAdapter;
            if (phoneBookAdapter2 != null) {
                phoneBookAdapter2.notifyDataSetChanged();
                return;
            }
            return;
        }
        if (id == NotificationCenter.closeChats) {
            removeSelfFromStack();
        }
    }

    public void setDelegate(PhoneBookSelectActivityDelegate delegate) {
        this.delegate = delegate;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        ThemeDescription.ThemeDescriptionDelegate cellDelegate = new ThemeDescription.ThemeDescriptionDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PhoneBookSelectActivity$hxri0EGG7pfLIHSYVaS5BSvK6Jc
            @Override // im.uwrkaxlmjj.ui.actionbar.ThemeDescription.ThemeDescriptionDelegate
            public final void didSetColor() {
                this.f$0.lambda$getThemeDescriptions$2$PhoneBookSelectActivity();
            }
        };
        return new ThemeDescription[]{new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCH, null, null, null, null, Theme.key_actionBarDefaultSearch), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCHPLACEHOLDER, null, null, null, null, Theme.key_actionBarDefaultSearchPlaceholder), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SECTIONS, new Class[]{LetterSectionCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.emptyView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_emptyListPlaceholder), new ThemeDescription(this.listView, ThemeDescription.FLAG_FASTSCROLL, null, null, null, null, Theme.key_fastScrollActive), new ThemeDescription(this.listView, ThemeDescription.FLAG_FASTSCROLL, null, null, null, null, Theme.key_fastScrollInactive), new ThemeDescription(this.listView, ThemeDescription.FLAG_FASTSCROLL, null, null, null, null, Theme.key_fastScrollText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, new String[]{"nameTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, new String[]{"statusColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteGrayText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, new String[]{"statusOnlineColor"}, (Paint[]) null, (Drawable[]) null, cellDelegate, Theme.key_windowBackgroundWhiteBlueText), new ThemeDescription(this.listView, 0, new Class[]{UserCell.class}, null, new Drawable[]{Theme.avatar_savedDrawable}, null, Theme.key_avatar_text), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundRed), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundOrange), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundViolet), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundGreen), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundCyan), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundBlue), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundPink)};
    }

    public /* synthetic */ void lambda$getThemeDescriptions$2$PhoneBookSelectActivity() {
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null) {
            int count = recyclerListView.getChildCount();
            for (int a = 0; a < count; a++) {
                View child = this.listView.getChildAt(a);
                if (child instanceof UserCell) {
                    ((UserCell) child).update(0);
                }
            }
        }
    }
}
