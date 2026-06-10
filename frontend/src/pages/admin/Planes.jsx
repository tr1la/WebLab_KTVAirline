import { useState, useEffect } from 'react';
import { FaPlus, FaEdit, FaTrash } from 'react-icons/fa';
import { getPlanes, createPlane, updatePlane, deletePlane } from '../../services/api';
import { toast } from 'react-toastify';

const PlaneForm = ({ onSubmit, initialData = null }) => {
  const [formData, setFormData] = useState({
    name: '',
    producer: '',
    diagramLink: '',
    summary: '',
    ...initialData
  });

  const handleSubmit = (e) => {
    e.preventDefault();
    // Đảm bảo các trường bắt buộc có giá trị
    if (!formData.name || !formData.producer) {
      toast.error('Vui lòng điền đầy đủ thông tin');
      return;
    }
    onSubmit(formData);
  };

  return (
    <form onSubmit={handleSubmit} className="bg-white p-6 rounded-lg shadow-md">
      <h3 className="text-xl font-semibold mb-4">
        {initialData ? 'Chỉnh sửa tàu bay' : 'Thêm tàu bay mới'}
      </h3>
      
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700">Tên tàu bay</label>
          <input
            type="text"
            value={formData.name || ''}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700">Nhà sản xuất</label>
          <input
            type="text"
            value={formData.producer || ''}
            onChange={(e) => setFormData({ ...formData, producer: e.target.value })}
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700">Link sơ đồ</label>
          <input
            type="url"
            value={formData.diagramLink || ''}
            onChange={(e) => setFormData({ ...formData, diagramLink: e.target.value })}
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700">Mô tả</label>
          <textarea
            value={formData.summary || ''}
            onChange={(e) => setFormData({ ...formData, summary: e.target.value })}
            rows={4}
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
          />
        </div>

        {initialData && (
          <div className="space-y-2 pt-4 border-t">
            <div className="text-sm text-gray-500">
              <span className="font-medium">Người tạo:</span> {formData.createBy || 'N/A'}
            </div>
            <div className="text-sm text-gray-500">
              <span className="font-medium">Ngày tạo:</span> {formData.createDate ? new Date(formData.createDate).toLocaleString('vi-VN') : 'N/A'}
            </div>
            <div className="text-sm text-gray-500">
              <span className="font-medium">Người cập nhật:</span> {formData.updateBy || 'N/A'}
            </div>
            <div className="text-sm text-gray-500">
              <span className="font-medium">Ngày cập nhật:</span> {formData.updateDate ? new Date(formData.updateDate).toLocaleString('vi-VN') : 'N/A'}
            </div>
          </div>
        )}

        <button
          type="submit"
          className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 transition-colors"
        >
          {initialData ? 'Cập nhật' : 'Thêm mới'}
        </button>
      </div>
    </form>
  );
};

const Planes = () => {
  const [planes, setPlanes] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [editingPlane, setEditingPlane] = useState(null);
  const [loading, setLoading] = useState(false);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(0);

  const fetchData = async () => {
    try {
      setLoading(true);
      const response = await getPlanes(page);
      if (response.data) {
        setPlanes(response.data);
        setTotalPages(Math.ceil(response.data.length / 10));
      }
    } catch (error) {
      const errorMessage = error.response?.data || error.message;
      toast.error('Không thể tải danh sách tàu bay: ' + errorMessage);
      console.error('Error fetching planes:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [page]);

  const handleSubmit = async (formData) => {
    try {
      setLoading(true);
      if (editingPlane) {
        await updatePlane({
          ...formData,
          id: editingPlane.id
        });
        toast.success('Cập nhật tàu bay thành công');
      } else {
        await createPlane(formData);
        toast.success('Thêm tàu bay thành công');
      }
      fetchData();
      setShowForm(false);
      setEditingPlane(null);
    } catch (error) {
      toast.error('Có lỗi xảy ra');
      console.error('Error submitting plane:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = (item) => {
    setShowForm(false);
    setEditingPlane(null);
    setTimeout(() => {
    setEditingPlane(item);
    setShowForm(true);
    }, 100);
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Bạn có chắc chắn muốn xóa tàu bay này?')) {
      return;
    }

    try {
      setLoading(true);
      await deletePlane(id);
      toast.success('Xóa tàu bay thành công');
      fetchData();
    } catch (error) {
      toast.error('Không thể xóa tàu bay');
      console.error('Error deleting plane:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAddNew = () => {
    setEditingPlane(null);
    setShowForm(false);
    setTimeout(() => {
      setShowForm(true);
    }, 100);
  };

  return (
    <div className="min-h-screen bg-gray-100 p-8">
      <div className="max-w-7xl mx-auto">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold text-gray-800">Quản lý tàu bay</h1>
          <button
            onClick={handleAddNew}
            className="flex items-center bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 transition-colors"
            disabled={loading}
          >
            <FaPlus className="mr-2" />
            Thêm tàu bay
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-2">
            <div className="bg-white rounded-lg shadow-md">
              <div className="p-6">
                {loading ? (
                  <div className="flex justify-center items-center h-32">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                  </div>
                ) : (
                  <table className="min-w-full">
                    <thead>
                      <tr>
                        <th className="text-left py-3 px-4 border-b">Tên tàu bay</th>
                        <th className="text-left py-3 px-4 border-b">Nhà sản xuất</th>
                        <th className="text-left py-3 px-4 border-b">Mô tả</th>
                        <th className="text-left py-3 px-4 border-b">Ngày cập nhật</th>
                        <th className="text-right py-3 px-4 border-b">Thao tác</th>
                      </tr>
                    </thead>
                    <tbody>
                      {planes.map((item) => (
                        <tr key={item.id} className="hover:bg-gray-50">
                          <td className="py-3 px-4 border-b">{item.name || 'N/A'}</td>
                          <td className="py-3 px-4 border-b">{item.producer || 'N/A'}</td>
                          <td className="py-3 px-4 border-b">
                            <div className="max-w-xs truncate">
                              {item.summary || 'Chưa có mô tả'}
                            </div>
                          </td>
                          <td className="py-3 px-4 border-b">
                            {item.updateDate ? new Date(item.updateDate).toLocaleString('vi-VN') : 'N/A'}
                          </td>
                          <td className="py-3 px-4 border-b text-right space-x-2">
                            <button
                              onClick={() => handleEdit(item)}
                              className="inline-flex items-center text-blue-600 hover:text-blue-800 mr-3"
                              disabled={loading}
                              title="Chỉnh sửa"
                            >
                              <FaEdit />
                            </button>
                            <button
                              onClick={() => handleDelete(item.id)}
                              className="inline-flex items-center text-red-600 hover:text-red-800"
                              disabled={loading}
                              title="Xóa"
                            >
                              <FaTrash />
                            </button>
                          </td>
                        </tr>
                      ))}
                      {planes.length === 0 && (
                        <tr>
                          <td colSpan="5" className="text-center py-8 text-gray-500">
                            Chưa có dữ liệu tàu bay
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          </div>

          {showForm && (
            <div className="lg:col-span-1">
              <PlaneForm onSubmit={handleSubmit} initialData={editingPlane} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Planes; 