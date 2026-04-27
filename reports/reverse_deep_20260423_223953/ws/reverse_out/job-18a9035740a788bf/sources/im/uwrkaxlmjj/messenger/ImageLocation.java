package im.uwrkaxlmjj.messenger;

import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;

/* JADX INFO: loaded from: classes2.dex */
public class ImageLocation {
    public long access_hash;
    public int currentSize;
    public int dc_id;
    public TLRPC.Document document;
    public long documentId;
    public byte[] file_reference;
    public byte[] iv;
    public byte[] key;
    public TLRPC.TL_fileLocationToBeDeprecated location;
    public boolean lottieAnimation;
    public String path;
    public TLRPC.Photo photo;
    public long photoId;
    public TLRPC.InputPeer photoPeer;
    public boolean photoPeerBig;
    public TLRPC.PhotoSize photoSize;
    public SecureDocument secureDocument;
    public TLRPC.InputStickerSet stickerSet;
    public String thumbSize;
    public WebFile webFile;

    public static ImageLocation getForPath(String path) {
        if (path == null) {
            return null;
        }
        ImageLocation imageLocation = new ImageLocation();
        imageLocation.path = path;
        return imageLocation;
    }

    public static ImageLocation getForSecureDocument(SecureDocument secureDocument) {
        if (secureDocument == null) {
            return null;
        }
        ImageLocation imageLocation = new ImageLocation();
        imageLocation.secureDocument = secureDocument;
        return imageLocation;
    }

    public static ImageLocation getForDocument(TLRPC.Document document) {
        if (document == null) {
            return null;
        }
        ImageLocation imageLocation = new ImageLocation();
        imageLocation.document = document;
        imageLocation.key = document.key;
        imageLocation.iv = document.iv;
        imageLocation.currentSize = document.size;
        return imageLocation;
    }

    public static ImageLocation getForWebFile(WebFile webFile) {
        if (webFile == null) {
            return null;
        }
        ImageLocation imageLocation = new ImageLocation();
        imageLocation.webFile = webFile;
        imageLocation.currentSize = webFile.size;
        return imageLocation;
    }

    public static ImageLocation getForObject(TLRPC.PhotoSize photoSize, TLObject object) {
        if (object instanceof TLRPC.Photo) {
            return getForPhoto(photoSize, (TLRPC.Photo) object);
        }
        if (object instanceof TLRPC.Document) {
            return getForDocument(photoSize, (TLRPC.Document) object);
        }
        return null;
    }

    public static ImageLocation getForPhoto(TLRPC.PhotoSize photoSize, TLRPC.Photo photo) {
        int dc_id;
        if (photoSize instanceof TLRPC.TL_photoStrippedSize) {
            ImageLocation imageLocation = new ImageLocation();
            imageLocation.photoSize = photoSize;
            return imageLocation;
        }
        if (photoSize == null || photo == null) {
            return null;
        }
        if (photo.dc_id != 0) {
            dc_id = photo.dc_id;
        } else {
            dc_id = photoSize.location.dc_id;
        }
        return getForPhoto(photoSize.location, photoSize.size, photo, null, null, false, dc_id, null, photoSize.type);
    }

    public static ImageLocation getForUser(TLRPC.User user, boolean big) {
        int dc_id;
        if (user == null || user.access_hash == 0 || user.photo == null) {
            return null;
        }
        TLRPC.UserProfilePhoto userProfilePhoto = user.photo;
        TLRPC.FileLocation fileLocation = big ? userProfilePhoto.photo_big : userProfilePhoto.photo_small;
        if (fileLocation == null) {
            return null;
        }
        TLRPC.TL_inputPeerUser inputPeer = new TLRPC.TL_inputPeerUser();
        inputPeer.user_id = user.id;
        inputPeer.access_hash = user.access_hash;
        if (user.photo.dc_id != 0) {
            dc_id = user.photo.dc_id;
        } else {
            int dc_id2 = fileLocation.dc_id;
            dc_id = dc_id2;
        }
        return getForPhoto(fileLocation, 0, null, null, inputPeer, big, dc_id, null, null);
    }

    public static ImageLocation getForChat(TLRPC.Chat chat, boolean big) {
        TLRPC.InputPeer inputPeer;
        int dc_id;
        if (chat == null || chat.photo == null) {
            return null;
        }
        TLRPC.ChatPhoto chatPhoto = chat.photo;
        TLRPC.FileLocation fileLocation = big ? chatPhoto.photo_big : chatPhoto.photo_small;
        if (fileLocation == null) {
            return null;
        }
        if (!ChatObject.isChannel(chat)) {
            inputPeer = new TLRPC.TL_inputPeerChat();
            inputPeer.chat_id = chat.id;
        } else {
            if (chat.access_hash == 0) {
                return null;
            }
            inputPeer = new TLRPC.TL_inputPeerChannel();
            inputPeer.channel_id = chat.id;
            inputPeer.access_hash = chat.access_hash;
        }
        if (chat.photo.dc_id != 0) {
            dc_id = chat.photo.dc_id;
        } else {
            int dc_id2 = fileLocation.dc_id;
            dc_id = dc_id2;
        }
        return getForPhoto(fileLocation, 0, null, null, inputPeer, big, dc_id, null, null);
    }

    public static ImageLocation getForSticker(TLRPC.PhotoSize photoSize, TLRPC.Document sticker) {
        TLRPC.InputStickerSet stickerSet;
        if (photoSize instanceof TLRPC.TL_photoStrippedSize) {
            ImageLocation imageLocation = new ImageLocation();
            imageLocation.photoSize = photoSize;
            return imageLocation;
        }
        if (photoSize == null || sticker == null || (stickerSet = MediaDataController.getInputStickerSet(sticker)) == null) {
            return null;
        }
        ImageLocation imageLocation2 = getForPhoto(photoSize.location, photoSize.size, null, null, null, false, sticker.dc_id, stickerSet, photoSize.type);
        if (MessageObject.isAnimatedStickerDocument(sticker)) {
            imageLocation2.lottieAnimation = true;
        }
        return imageLocation2;
    }

    public static ImageLocation getForDocument(TLRPC.PhotoSize photoSize, TLRPC.Document document) {
        if (photoSize instanceof TLRPC.TL_photoStrippedSize) {
            ImageLocation imageLocation = new ImageLocation();
            imageLocation.photoSize = photoSize;
            return imageLocation;
        }
        if (photoSize == null || document == null) {
            return null;
        }
        return getForPhoto(photoSize.location, photoSize.size, null, document, null, false, document.dc_id, null, photoSize.type);
    }

    public static ImageLocation getForLocal(TLRPC.FileLocation location) {
        if (location == null) {
            return null;
        }
        ImageLocation imageLocation = new ImageLocation();
        TLRPC.TL_fileLocationToBeDeprecated tL_fileLocationToBeDeprecated = new TLRPC.TL_fileLocationToBeDeprecated();
        imageLocation.location = tL_fileLocationToBeDeprecated;
        tL_fileLocationToBeDeprecated.local_id = location.local_id;
        imageLocation.location.volume_id = location.volume_id;
        imageLocation.location.secret = location.secret;
        imageLocation.location.dc_id = location.dc_id;
        return imageLocation;
    }

    private static ImageLocation getForPhoto(TLRPC.FileLocation location, int size, TLRPC.Photo photo, TLRPC.Document document, TLRPC.InputPeer photoPeer, boolean photoPeerBig, int dc_id, TLRPC.InputStickerSet stickerSet, String thumbSize) {
        if (location == null) {
            return null;
        }
        if (photo == null && photoPeer == null && stickerSet == null && document == null) {
            return null;
        }
        ImageLocation imageLocation = new ImageLocation();
        imageLocation.dc_id = dc_id;
        imageLocation.photo = photo;
        imageLocation.currentSize = size;
        imageLocation.photoPeer = photoPeer;
        imageLocation.photoPeerBig = photoPeerBig;
        imageLocation.stickerSet = stickerSet;
        if (location instanceof TLRPC.TL_fileLocationToBeDeprecated) {
            imageLocation.location = (TLRPC.TL_fileLocationToBeDeprecated) location;
            if (photo != null) {
                imageLocation.file_reference = photo.file_reference;
                imageLocation.access_hash = photo.access_hash;
                imageLocation.photoId = photo.id;
                imageLocation.thumbSize = thumbSize;
            } else if (document != null) {
                imageLocation.file_reference = document.file_reference;
                imageLocation.access_hash = document.access_hash;
                imageLocation.documentId = document.id;
                imageLocation.thumbSize = thumbSize;
            }
        } else {
            TLRPC.TL_fileLocationToBeDeprecated tL_fileLocationToBeDeprecated = new TLRPC.TL_fileLocationToBeDeprecated();
            imageLocation.location = tL_fileLocationToBeDeprecated;
            tL_fileLocationToBeDeprecated.local_id = location.local_id;
            imageLocation.location.volume_id = location.volume_id;
            imageLocation.location.secret = location.secret;
            imageLocation.dc_id = location.dc_id;
            imageLocation.file_reference = location.file_reference;
            imageLocation.key = location.key;
            imageLocation.iv = location.iv;
            imageLocation.access_hash = location.secret;
        }
        return imageLocation;
    }

    public static String getStippedKey(Object parentObject, Object fullObject, Object strippedObject) {
        if (parentObject instanceof TLRPC.WebPage) {
            if (fullObject instanceof ImageLocation) {
                ImageLocation imageLocation = (ImageLocation) fullObject;
                if (imageLocation.document != null) {
                    fullObject = imageLocation.document;
                } else if (imageLocation.photoSize != null) {
                    fullObject = imageLocation.photoSize;
                } else if (imageLocation.photo != null) {
                    fullObject = imageLocation.photo;
                }
            }
            if (fullObject == null) {
                return "stripped" + FileRefController.getKeyForParentObject(parentObject) + "_" + strippedObject;
            }
            if (fullObject instanceof TLRPC.Document) {
                TLRPC.Document document = (TLRPC.Document) fullObject;
                return "stripped" + FileRefController.getKeyForParentObject(parentObject) + "_" + document.id;
            }
            if (fullObject instanceof TLRPC.Photo) {
                TLRPC.Photo photo = (TLRPC.Photo) fullObject;
                return "stripped" + FileRefController.getKeyForParentObject(parentObject) + "_" + photo.id;
            }
            if (fullObject instanceof TLRPC.PhotoSize) {
                TLRPC.PhotoSize size = (TLRPC.PhotoSize) fullObject;
                if (size.location != null) {
                    return "stripped" + FileRefController.getKeyForParentObject(parentObject) + "_" + size.location.local_id + "_" + size.location.volume_id;
                }
                return "stripped" + FileRefController.getKeyForParentObject(parentObject);
            }
            if (fullObject instanceof TLRPC.FileLocation) {
                TLRPC.FileLocation loc = (TLRPC.FileLocation) fullObject;
                return "stripped" + FileRefController.getKeyForParentObject(parentObject) + "_" + loc.local_id + "_" + loc.volume_id;
            }
        }
        return "stripped" + FileRefController.getKeyForParentObject(parentObject);
    }

    public String getKey(Object parentObject, Object fullObject) {
        if (this.secureDocument != null) {
            return this.secureDocument.secureFile.dc_id + "_" + this.secureDocument.secureFile.id;
        }
        TLRPC.PhotoSize photoSize = this.photoSize;
        if (photoSize instanceof TLRPC.TL_photoStrippedSize) {
            if (photoSize.bytes.length > 0) {
                return getStippedKey(parentObject, fullObject, this.photoSize);
            }
            return null;
        }
        if (this.location != null) {
            return this.location.volume_id + "_" + this.location.local_id;
        }
        WebFile webFile = this.webFile;
        if (webFile != null) {
            return Utilities.MD5(webFile.url);
        }
        TLRPC.Document document = this.document;
        if (document == null) {
            String str = this.path;
            if (str != null) {
                return Utilities.MD5(str);
            }
            return null;
        }
        if (document.id != 0 && this.document.dc_id != 0) {
            return this.document.dc_id + "_" + this.document.id;
        }
        return null;
    }

    public boolean isEncrypted() {
        return this.key != null;
    }

    public int getSize() {
        TLRPC.PhotoSize photoSize = this.photoSize;
        if (photoSize != null) {
            return photoSize.size;
        }
        SecureDocument secureDocument = this.secureDocument;
        if (secureDocument != null) {
            if (secureDocument.secureFile != null) {
                return this.secureDocument.secureFile.size;
            }
        } else {
            TLRPC.Document document = this.document;
            if (document != null) {
                return document.size;
            }
            WebFile webFile = this.webFile;
            if (webFile != null) {
                return webFile.size;
            }
        }
        return this.currentSize;
    }
}
