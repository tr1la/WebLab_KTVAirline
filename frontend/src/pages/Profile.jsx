import { useState, useEffect } from 'react';
import { FaUser, FaEnvelope, FaIdCard, FaKey, FaPhone, FaCalendar, FaVenusMars, FaMapMarkerAlt } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { useAuth } from '../contexts/AuthContext';
import { getUserByEmail, updateUser, changePassword } from '../services/api';
import { useNavigate } from 'react-router-dom';

const ProfileSection = ({ title, children }) => (
  <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
    <div className="px-6 py-4 border-b border-gray-200">
      <h2 className="text-lg font-semibold text-gray-900">{title}</h2>
    </div>
    <div className="p-6">{children}</div>
  </div>
);

const InputField = ({ icon: Icon, label, type = "text", value, onChange, disabled = false, error = "", as = "input" }) => {
  const commonClasses = `block w-full pl-10 pr-3 py-2 sm:text-sm rounded-lg
    ${disabled 
      ? 'bg-gray-100 text-gray-500 cursor-not-allowed' 
      : 'bg-white focus:ring-2 focus:ring-[#605DEC] focus:border-[#605DEC]'
    }
    ${error ? 'border-red-300' : 'border-gray-300'}
    transition-colors duration-200
  `;

  return (
    <div className="space-y-1">
      <label className="block text-sm font-medium text-gray-700">{label}</label>
      <div className="relative rounded-lg shadow-sm">
        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          <Icon className="h-5 w-5 text-gray-400" />
        </div>
        {as === "select" ? (
          <select
            value={value || ''}
            onChange={onChange}
            disabled={disabled}
            className={commonClasses}
          >
            <option value="">Chọn giới tính</option>
            <option value="MALE">Nam</option>
            <option value="FEMALE">Nữ</option>
            <option value="OTHER">Khác</option>
          </select>
        ) : as === "textarea" ? (
          <textarea
            value={value || ''}
            onChange={onChange}
            disabled={disabled}
            className={`${commonClasses} resize-none h-20`}
          />
        ) : (
          <input
            type={type}
            value={value || ''}
            onChange={onChange}
            disabled={disabled}
            className={commonClasses}
          />
        )}
      </div>
      {error && <p className="text-sm text-red-600 mt-1">{error}</p>}
    </div>
  );
};

const Profile = () => {
  const { user, setUser } = useAuth();
  const [isEditing, setIsEditing] = useState(false);
  const [isChangingPassword, setIsChangingPassword] = useState(false);
  const [errors, setErrors] = useState({});
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    idNumber: '',
    birthday: '',
    phoneNum: '',
    gender: '',
    address: '',
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });
  const navigate = useNavigate();

  useEffect(() => {
    const fetchUserData = async () => {
      try {
        if (user?.email) {
          const response = await getUserByEmail(user.email);
          const userData = response.data;
          setFormData({
            name: userData.name || '',
            email: userData.email || '',
            idNumber: userData.idNumber || '',
            birthday: userData.birthday ? new Date(userData.birthday).toISOString().split('T')[0] : '',
            phoneNum: userData.phoneNum || '',
            gender: userData.gender || '',
            address: userData.address || '',
            currentPassword: '',
            newPassword: '',
            confirmPassword: ''
          });
        }
      } catch (error) {
        console.error('Error fetching user data:', error);
        toast.error('Không thể tải thông tin người dùng');
      }
    };

    fetchUserData();
  }, [user]);

  const handleInputChange = (field) => (e) => {
    setFormData(prev => ({ ...prev, [field]: e.target.value }));
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: '' }));
    }
  };

  const validateForm = () => {
    const newErrors = {};
    
    if (!formData.name.trim()) {
      newErrors.name = 'Vui lòng nhập họ tên';
    }

    if (isChangingPassword) {
      if (!formData.currentPassword) {
        newErrors.currentPassword = 'Vui lòng nhập mật khẩu hiện tại';
      }
      if (!formData.newPassword) {
        newErrors.newPassword = 'Vui lòng nhập mật khẩu mới';
      } else if (formData.newPassword.length < 6) {
        newErrors.newPassword = 'Mật khẩu phải có ít nhất 6 ký tự';
      }
      if (!formData.confirmPassword) {
        newErrors.confirmPassword = 'Vui lòng xác nhận mật khẩu';
      } else if (formData.newPassword !== formData.confirmPassword) {
        newErrors.confirmPassword = 'Mật khẩu xác nhận không khớp';
      }
    }

    if (isEditing) {
      if (!formData.phoneNum) {
        newErrors.phoneNum = 'Vui lòng nhập số điện thoại';
      }
      if (!formData.birthday) {
        newErrors.birthday = 'Vui lòng chọn ngày sinh';
      }
      if (!formData.gender) {
        newErrors.gender = 'Vui lòng chọn giới tính';
      }
      if (!formData.address) {
        newErrors.address = 'Vui lòng nhập địa chỉ';
      }
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    try {
      if (isChangingPassword) {
        try {
          await changePassword({
            email: user.email,
            oldPassword: formData.currentPassword,
            newPassword: formData.newPassword
          });
          toast.success('Đổi mật khẩu thành công!');
          setIsChangingPassword(false);
          setFormData(prev => ({
            ...prev,
            currentPassword: '',
            newPassword: '',
            confirmPassword: ''
          }));
        } catch (error) {
          console.error('Password change error:', error);
          let errorMessage = 'Có lỗi xảy ra khi đổi mật khẩu';
          
          if (error.response?.status === 400) {
            errorMessage = 'Mật khẩu hiện tại không đúng';
          } else if (error.response?.status === 401 || error.response?.status === 403) {
            errorMessage = 'Phiên đăng nhập đã hết hạn, vui lòng đăng nhập lại';
            localStorage.removeItem('token');
            navigate('/login');
          } else if (error.response?.data) {
            errorMessage = error.response.data;
          }
          
          toast.error(errorMessage);
          return;
        }
      } else {
        const updateData = {
          id: user.id,
          email: user.email,
          name: formData.name,
          idNumber: formData.idNumber,
          birthday: formData.birthday,
          phoneNum: formData.phoneNum,
          gender: formData.gender,
          address: formData.address,
          role: user.role,
          createBy: user.createBy,
          createDate: user.createDate,
          updateBy: user.email,
          updateDate: new Date().toISOString(),
          forgotten: user.forgotten || false,
          deleted: user.deleted || false
        };
        
        const response = await updateUser(updateData);
        if (response.data === "Edited") {
          const updatedUserResponse = await getUserByEmail(user.email);
          setUser(updatedUserResponse.data);
          toast.success('Cập nhật thông tin thành công!');
          setIsEditing(false);
        }
      }
    } catch (error) {
      console.error('Error updating profile:', error);
      const errorMessage = error.response?.data || 'Có lỗi xảy ra. Vui lòng thử lại!';
      toast.error(errorMessage);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="space-y-6">
          {/* Profile Header */}
          <div className="flex items-center justify-between">
            <h1 className="text-2xl font-bold text-gray-900">Thông tin cá nhân</h1>
            <div className="space-x-4">
              <button
                onClick={() => {
                  setIsEditing(!isEditing);
                  setIsChangingPassword(false);
                }}
                className={`px-4 py-2 rounded-lg font-medium text-sm transition-colors duration-200
                  ${isEditing
                    ? 'bg-gray-200 text-gray-600 hover:bg-gray-300'
                    : 'bg-[#605DEC] text-white hover:bg-[#4B48BF]'
                  }`}
              >
                {isEditing ? 'Hủy' : 'Chỉnh sửa'}
              </button>
              <button
                onClick={() => {
                  setIsChangingPassword(!isChangingPassword);
                  setIsEditing(false);
                }}
                className={`px-4 py-2 rounded-lg font-medium text-sm transition-colors duration-200
                  ${isChangingPassword
                    ? 'bg-gray-200 text-gray-600 hover:bg-gray-300'
                    : 'bg-[#605DEC] text-white hover:bg-[#4B48BF]'
                  }`}
              >
                {isChangingPassword ? 'Hủy' : 'Đổi mật khẩu'}
              </button>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Basic Information */}
            <ProfileSection title="Thông tin cơ bản">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <InputField
                  icon={FaUser}
                  label="Họ và tên"
                  value={formData.name}
                  onChange={handleInputChange('name')}
                  disabled={!isEditing}
                  error={errors.name}
                />
                <InputField
                  icon={FaEnvelope}
                  label="Email"
                  type="email"
                  value={formData.email}
                  disabled={true}
                />
                <InputField
                  icon={FaIdCard}
                  label="Mã định danh"
                  value={formData.idNumber}
                  disabled={true}
                />
                <InputField
                  icon={FaPhone}
                  label="Số điện thoại"
                  value={formData.phoneNum}
                  onChange={handleInputChange('phoneNum')}
                  disabled={!isEditing}
                  error={errors.phoneNum}
                />
                <InputField
                  icon={FaCalendar}
                  label="Ngày sinh"
                  type="date"
                  value={formData.birthday}
                  onChange={handleInputChange('birthday')}
                  disabled={!isEditing}
                  error={errors.birthday}
                />
                <InputField
                  icon={FaVenusMars}
                  label="Giới tính"
                  value={formData.gender}
                  onChange={handleInputChange('gender')}
                  disabled={!isEditing}
                  error={errors.gender}
                  as="select"
                />
                <div className="md:col-span-2">
                  <InputField
                    icon={FaMapMarkerAlt}
                    label="Địa chỉ"
                    value={formData.address}
                    onChange={handleInputChange('address')}
                    disabled={!isEditing}
                    error={errors.address}
                    as="textarea"
                  />
                </div>
              </div>
            </ProfileSection>

            {/* Password Change Section */}
            {isChangingPassword && (
              <ProfileSection title="Đổi mật khẩu">
                <div className="space-y-6">
                  <InputField
                    icon={FaKey}
                    label="Mật khẩu hiện tại"
                    type="password"
                    value={formData.currentPassword}
                    onChange={handleInputChange('currentPassword')}
                    error={errors.currentPassword}
                  />
                  <InputField
                    icon={FaKey}
                    label="Mật khẩu mới"
                    type="password"
                    value={formData.newPassword}
                    onChange={handleInputChange('newPassword')}
                    error={errors.newPassword}
                  />
                  <InputField
                    icon={FaKey}
                    label="Xác nhận mật khẩu mới"
                    type="password"
                    value={formData.confirmPassword}
                    onChange={handleInputChange('confirmPassword')}
                    error={errors.confirmPassword}
                  />
                </div>
              </ProfileSection>
            )}

            {/* Submit Button */}
            {(isEditing || isChangingPassword) && (
              <div className="flex justify-end">
                <button
                  type="submit"
                  className="px-6 py-2 bg-[#605DEC] text-white rounded-lg hover:bg-[#4B48BF] transition-colors duration-200"
                >
                  {isChangingPassword ? 'Đổi mật khẩu' : 'Lưu thay đổi'}
                </button>
              </div>
            )}
          </form>
        </div>
      </div>
    </div>
  );
};

export default Profile;
