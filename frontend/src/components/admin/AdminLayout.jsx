import { Link, Outlet, useLocation } from 'react-router-dom';
import { FaNewspaper, FaPlane, FaCalendarAlt, FaTicketAlt, FaClock, FaTachometerAlt } from 'react-icons/fa';

const Sidebar = () => {
  const location = useLocation();
  
  const menuItems = [
    { path: '/admin', icon: FaTachometerAlt, label: 'Dashboard' },
    { path: '/admin/news', icon: FaNewspaper, label: 'Tin tức' },
    { path: '/admin/planes', icon: FaPlane, label: 'Tàu bay' },
    { path: '/admin/flights', icon: FaCalendarAlt, label: 'Chuyến bay' },
    { path: '/admin/bookings', icon: FaTicketAlt, label: 'Đặt vé' },
  ];

  return (
    <div className="w-64 bg-gray-800 min-h-screen fixed left-0 top-0">
      <div className="p-4">
        <h2 className="text-white text-2xl font-bold mb-8">KTVAirline Admin</h2>
        <nav>
          {menuItems.map((item) => (
            <Link
              key={item.path}
              to={item.path}
              className={`flex items-center text-gray-300 py-3 px-4 rounded-lg mb-2 hover:bg-gray-700 transition-colors ${
                location.pathname === item.path ? 'bg-gray-700' : ''
              }`}
            >
              <item.icon className="mr-3" />
              <span>{item.label}</span>
            </Link>
          ))}
        </nav>
      </div>
    </div>
  );
};

const AdminLayout = () => {
  return (
    <div className="flex">
      <Sidebar />
      <div className="ml-64 flex-1">
        <Outlet />
      </div>
    </div>
  );
};

export default AdminLayout; 
