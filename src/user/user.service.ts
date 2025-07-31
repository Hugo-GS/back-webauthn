import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './user.entity';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
  ) {}

  async create(userData: Partial<User>): Promise<User> {
    if (!userData.password) {
      throw new BadRequestException('Password is required');
    }
    const hashedPassword = await bcrypt.hash(userData.password, 10);
    const newUser = this.usersRepository.create({
      ...userData,
      password: hashedPassword,
    });
    return this.usersRepository.save(newUser);
  }

  async findOne(email: string): Promise<User | null> {
    return this.usersRepository.findOne({ where: { email } });
  }

  async findOneById(id: number): Promise<User | null> {
    return this.usersRepository.findOne({ where: { id } });
  }

  async update(id: number, userData: Partial<User>): Promise<User> {
    await this.usersRepository.update(id, userData);
    const updatedUser = await this.findOneById(id);
    if (!updatedUser) {
      throw new BadRequestException(`User with ID ${id} not found`);
    }
    return updatedUser;
  }
}
