/*
  # Initial Schema for Financial Management App

  1. New Tables
    - `profiles`
      - `id` (uuid, references auth.users)
      - `email` (text)
      - `full_name` (text)
      - `avatar_url` (text)
      - `created_at` (timestamp)
      - `updated_at` (timestamp)
    
    - `categories`
      - `id` (uuid, primary key)
      - `user_id` (uuid, references profiles)
      - `name` (text)
      - `type` (text, expense/income)
      - `monthly_limit` (numeric, optional)
      - `color` (text)
      - `created_at` (timestamp)
    
    - `transactions`
      - `id` (uuid, primary key)
      - `user_id` (uuid, references profiles)
      - `type` (text, expense/income/loan)
      - `amount` (numeric)
      - `description` (text)
      - `category_id` (uuid, references categories)
      - `date` (date)
      - `created_at` (timestamp)
    
    - `shared_access`
      - `id` (uuid, primary key)
      - `owner_id` (uuid, references profiles)
      - `shared_with_email` (text)
      - `shared_with_id` (uuid, references profiles, optional)
      - `permission` (text, read_only)
      - `status` (text, pending/accepted)
      - `created_at` (timestamp)

  2. Security
    - Enable RLS on all tables
    - Add policies for user data access
    - Add policies for shared access
*/

-- Create profiles table
CREATE TABLE IF NOT EXISTS profiles (
  id uuid REFERENCES auth.users ON DELETE CASCADE PRIMARY KEY,
  email text UNIQUE NOT NULL,
  full_name text,
  avatar_url text,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

-- Create categories table
CREATE TABLE IF NOT EXISTS categories (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  name text NOT NULL,
  type text NOT NULL CHECK (type IN ('expense', 'income')),
  monthly_limit numeric,
  color text NOT NULL DEFAULT '#3B82F6',
  created_at timestamptz DEFAULT now()
);

-- Create transactions table
CREATE TABLE IF NOT EXISTS transactions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  type text NOT NULL CHECK (type IN ('expense', 'income', 'loan')),
  amount numeric NOT NULL CHECK (amount > 0),
  description text NOT NULL,
  category_id uuid REFERENCES categories(id) ON DELETE SET NULL,
  date date NOT NULL,
  created_at timestamptz DEFAULT now()
);

-- Create shared_access table
CREATE TABLE IF NOT EXISTS shared_access (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id uuid REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  shared_with_email text NOT NULL,
  shared_with_id uuid REFERENCES profiles(id) ON DELETE CASCADE,
  permission text NOT NULL DEFAULT 'read_only' CHECK (permission IN ('read_only')),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted')),
  created_at timestamptz DEFAULT now()
);

-- Enable Row Level Security
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE shared_access ENABLE ROW LEVEL SECURITY;

-- Profiles policies
CREATE POLICY "Users can read own profile"
  ON profiles
  FOR SELECT
  TO authenticated
  USING (auth.uid() = id);

CREATE POLICY "Users can update own profile"
  ON profiles
  FOR UPDATE
  TO authenticated
  USING (auth.uid() = id);

CREATE POLICY "Users can insert own profile"
  ON profiles
  FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = id);

-- Categories policies
CREATE POLICY "Users can manage own categories"
  ON categories
  FOR ALL
  TO authenticated
  USING (user_id = auth.uid());

CREATE POLICY "Users can view shared categories"
  ON categories
  FOR SELECT
  TO authenticated
  USING (
    user_id = auth.uid() OR
    user_id IN (
      SELECT owner_id FROM shared_access 
      WHERE shared_with_id = auth.uid() AND status = 'accepted'
    )
  );

-- Transactions policies
CREATE POLICY "Users can manage own transactions"
  ON transactions
  FOR ALL
  TO authenticated
  USING (user_id = auth.uid());

CREATE POLICY "Users can view shared transactions"
  ON transactions
  FOR SELECT
  TO authenticated
  USING (
    user_id = auth.uid() OR
    user_id IN (
      SELECT owner_id FROM shared_access 
      WHERE shared_with_id = auth.uid() AND status = 'accepted'
    )
  );

-- Shared access policies
CREATE POLICY "Users can manage their sharing settings"
  ON shared_access
  FOR ALL
  TO authenticated
  USING (owner_id = auth.uid());

CREATE POLICY "Users can view shares directed to them"
  ON shared_access
  FOR SELECT
  TO authenticated
  USING (shared_with_id = auth.uid() OR owner_id = auth.uid());

CREATE POLICY "Users can update shares directed to them"
  ON shared_access
  FOR UPDATE
  TO authenticated
  USING (shared_with_id = auth.uid())
  WITH CHECK (shared_with_id = auth.uid());

-- Function to handle new user registration
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS trigger AS $$
BEGIN
  INSERT INTO profiles (id, email, full_name, avatar_url)
  VALUES (
    new.id,
    new.email,
    new.raw_user_meta_data->>'full_name',
    new.raw_user_meta_data->>'avatar_url'
  );
  RETURN new;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger for new user registration
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION handle_new_user();

-- Function to update shared_access when user signs up
CREATE OR REPLACE FUNCTION update_shared_access_on_signup()
RETURNS trigger AS $$
BEGIN
  UPDATE shared_access 
  SET shared_with_id = new.id
  WHERE shared_with_email = new.email AND shared_with_id IS NULL;
  RETURN new;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger to update shared access
DROP TRIGGER IF EXISTS on_profile_created ON profiles;
CREATE TRIGGER on_profile_created
  AFTER INSERT ON profiles
  FOR EACH ROW EXECUTE FUNCTION update_shared_access_on_signup();