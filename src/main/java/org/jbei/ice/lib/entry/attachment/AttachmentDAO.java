package org.jbei.ice.lib.entry.attachment;

import org.apache.commons.io.IOUtils;
import org.hibernate.HibernateException;
import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.criterion.Projections;
import org.hibernate.criterion.Restrictions;
import org.jbei.ice.lib.dao.DAOException;
import org.jbei.ice.lib.entry.model.Entry;
import org.jbei.ice.lib.managers.ManagerException;
import org.jbei.ice.lib.utils.JbeirSettings;
import org.jbei.ice.lib.utils.Utils;
import org.jbei.ice.server.dao.hibernate.HibernateRepository;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Manager to manipulate {@link Attachment} objects in the database.
 *
 * @author Timothy Ham, Zinovii Dmytriv
 */
public class AttachmentDAO extends HibernateRepository {

    private static final String ATTACHMENTS_DIR = JbeirSettings.getSetting("ATTACHMENTS_DIRECTORY");

    /**
     * Save the {@link Attachment} in the databse, and {@link InputStream} to the disk.
     *
     * @param attachment
     * @param inputStream
     * @return Saved Attachment.
     * @throws DAOException
     */
    public Attachment save(Attachment attachment, InputStream inputStream)
            throws DAOException {
        if (attachment == null) {
            throw new DAOException("Failed to save null attachment!");
        }

        if (attachment.getFileId() == null || attachment.getFileId() == "") {
            String fileId = Utils.generateUUID();
            attachment.setFileId(fileId);
        }

        Attachment result;

        try {
            writeAttachmentToFile(attachment.getFileId(), inputStream);

            result = (Attachment) super.saveOrUpdate(attachment);
        } catch (IOException e) {
            throw new DAOException("Failed to create attachment file!", e);
        } catch (DAOException e) {
            try {
                deleteAttachmentFile(attachment);
            } catch (IOException e1) {
                throw new DAOException(e);
            }

            throw new DAOException("Failed to save attachment!", e);
        }

        return result;
    }

    /**
     * Delete the given {@link Attachment} from the database, and the file from the disk.
     *
     * @param attachment
     * @throws ManagerException
     */
    public void delete(Attachment attachment) throws DAOException {
        if (attachment == null) {
            throw new DAOException("Failed to delete null attachment!");
        }

        try {
            super.delete(attachment);
            deleteAttachmentFile(attachment);
        } catch (IOException e) {
            throw new DAOException("Failed to delete attachment file!", e);
        }
    }

    /**
     * Retrieve all {@link Attachment}s associated with the given {@link Entry}.
     *
     * @param entry
     * @return ArrayList of Attachments.
     * @throws ManagerException
     */
    @SuppressWarnings("unchecked")
    public ArrayList<Attachment> getByEntry(Entry entry) throws DAOException {
        ArrayList<Attachment> attachments = null;

        Session session = newSession();
        try {
            String queryString = "from " + Attachment.class.getName()
                    + " as attachment where attachment.entry = :entry order by attachment.id desc";

            Query query = session.createQuery(queryString);
            query.setEntity("entry", entry);
            @SuppressWarnings("rawtypes")
            List list = query.list();

            if (list != null) {
                attachments = (ArrayList<Attachment>) list;
            }
        } catch (HibernateException e) {
            throw new DAOException("Failed to retrieve attachment by entry: " + entry.getId(), e);
        } finally {
            if (session.isOpen()) {
                session.close();
            }
        }

        return attachments;
    }

    public boolean hasAttachment(Entry entry) throws DAOException {
        Session session = newSession();
        try {

            Integer itemCount = (Integer) session.createCriteria(Attachment.class)
                                                 .setProjection(Projections.countDistinct("id"))
                                                 .add(Restrictions.eq("entry", entry)).uniqueResult();

            return itemCount.intValue() > 0;
        } catch (HibernateException e) {
            throw new DAOException("Failed to retrieve attachment by entry: " + entry.getId(),
                                   e);
        } finally {
            if (session.isOpen()) {
                session.close();
            }
        }
    }

    /**
     * Retrieves attachment referenced by a unique file identifier
     *
     * @param fileId unique file identifier
     * @return retrieved attachment; null if none is found or there is a problem retrieving
     *         attachment
     * @throws ManagerException on Hibernate exception
     */
    public Attachment getByFileId(String fileId) throws DAOException {
        Attachment attachment = null;

        Session session = newSession();
        try {
            Query query = session.createQuery("from " + Attachment.class.getName()
                                                      + " where fileId = :fileId");

            query.setParameter("fileId", fileId);

            Object queryResult = query.uniqueResult();

            if (queryResult != null) {
                attachment = (Attachment) queryResult;
            }
        } catch (HibernateException e) {
            throw new DAOException("Failed to retrieve attachment by fileId: " + fileId, e);
        } finally {
            if (session.isOpen()) {
                session.close();
            }
        }

        return attachment;
    }

    /**
     * Retrieve the {@link File} from the disk of the given {@link Attachment}.
     *
     * @param attachment
     * @return File
     * @throws ManagerException
     */
    public File getFile(Attachment attachment) throws DAOException {
        File file = new File(ATTACHMENTS_DIR + File.separator + attachment.getFileId());

        if (!file.canRead()) {
            throw new DAOException("Failed to open file for read!");
        }

        return file;
    }

    /**
     * Write the given {@link InputStream} to the file with the given fileName.
     *
     * @param fileName
     * @param inputStream
     * @throws IOException
     * @throws DAOException
     */
    private void writeAttachmentToFile(String fileName, InputStream inputStream)
            throws IOException, DAOException {
        try {
            File file = new File(ATTACHMENTS_DIR + File.separator + fileName);

            File fileDir = new File(ATTACHMENTS_DIR);

            if (!fileDir.exists()) {
                if (!fileDir.mkdirs()) {
                    throw new DAOException("Could not create attachment directory");
                }
            }

            if (!file.exists()) {
                if (!file.createNewFile()) {
                    throw new DAOException("Could not create attachment file " + file.getName());
                }
            }

            FileOutputStream outputStream = new FileOutputStream(file);

            try {
                IOUtils.copy(inputStream, outputStream);
            } finally {
                outputStream.close();
            }
        } catch (SecurityException e) {
            throw new DAOException(e);
        }
    }

    /**
     * Delete the file on disk associated with the {@link Attachment}.
     *
     * @param attachment
     * @throws IOException
     * @throws DAOException
     */
    private void deleteAttachmentFile(Attachment attachment) throws IOException,
            DAOException {
        try {
            File file = new File(ATTACHMENTS_DIR + File.separator + attachment.getFileId());
            file.delete();
        } catch (SecurityException e) {
            throw new DAOException(e);
        }
    }
}